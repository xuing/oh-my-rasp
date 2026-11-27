package io.ohmyrasp.agent.hookmiss;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The run-time hook-miss report: one diagnostic line per (hook unit, class) per JVM when a unit that is meant to
 * instrument a loaded library class did not, so a library release that renamed or changed a hooked method is
 * reported where it runs instead of passing silently.
 *
 * <p>What counts as a miss is decided by the transformers: a class of the {@link HookExpectations} table that the
 * unit selects by name went through the unit and gained no call into the agent. They call {@link #miss} on the
 * class-loading thread, where it only marks the pair and queues it: no I/O, no formatting, no class of the agent
 * loaded for the first time (on a backport line every class here is preloaded). A worker thread, started when the
 * first miss is queued and ended when the queue is empty, does the rest: it lists the class's methods with the
 * names the unit looks for, reads the {@code Implementation-Version} of the JAR the class came from, and writes the
 * line through the line's {@link HookMissSink}. Anything the worker throws is dropped with its line.
 *
 * <p>At most {@link #LIMIT} lines per JVM, then one {@code hook_miss_suppressed} line and nothing more: the table
 * holds a few hundred pairs, a library release that breaks a hook usually breaks one to a few classes, and the cap
 * keeps a JVM that runs many such libraries to a few dozen lines (each a few hundred bytes to about 2 KiB).
 */
public final class HookMisses {
  /** The most hook-miss lines a JVM writes before the one suppressed line. */
  public static final int LIMIT = 32;
  /** The most methods listed in {@code looked_for} or {@code found}. */
  static final int MAX_LISTED = 16;
  /** The longest text member, in characters, before it is cut. */
  static final int MAX_TEXT = 512;

  /** The unit ran and none of the class's methods gained a call into the agent. */
  public static final String NO_AGENT_CALL = "no_agent_call";
  /** A backport transformer returned no bytes: it matched no method, or it failed and said so only with ohmyrasp.debug. */
  public static final String NOT_TRANSFORMED = "not_transformed";
  /** The primary transformer threw while it rewrote the class. */
  public static final String TRANSFORM_FAILED = "transform_failed";

  private static final Object LOCK = new Object();
  private static volatile HookExpectations table;
  // Guarded by LOCK.
  private static HookMissSink sink;
  private static boolean inline;
  private static final Set<HookExpectation> SEEN = new HashSet<HookExpectation>();
  private static final List<Candidate> PENDING = new ArrayList<Candidate>();
  private static boolean draining;
  private static int written;
  private static boolean suppressed;

  private HookMisses() {}

  /** Turns the report on, with the line's table and writer. A line's entry class calls it before it adds a transformer. */
  public static void start(HookExpectations expectations, HookMissSink target) {
    start(expectations, target, false);
  }

  /**
   * As {@link #start(HookExpectations, HookMissSink)}; with {@code writeInline} each line is written on the thread
   * that reports the miss and what the writer throws reaches that thread, for tests and the hook-targets probe.
   */
  public static void start(HookExpectations expectations, HookMissSink target, boolean writeInline) {
    synchronized (LOCK) {
      SEEN.clear();
      PENDING.clear();
      written = 0;
      suppressed = false;
      inline = writeInline;
      sink = target;
      table = expectations;
    }
  }

  /** Turns the report off; lines not yet written are dropped. */
  public static void stop() {
    synchronized (LOCK) {
      table = null;
      sink = null;
      PENDING.clear();
    }
  }

  /** Starts counting again, as in a new JVM: every pair can be reported once more, and the limit starts from zero. */
  public static void forget() {
    synchronized (LOCK) {
      SEEN.clear();
      written = 0;
      suppressed = false;
    }
  }

  /** The table while the report is on, else null. A transformer reads it once per class it transforms. */
  public static HookExpectations table() {
    return table;
  }

  /**
   * On the class-loading thread: {@code unit}, the unit of {@code expectation} under its own name (a backport
   * transformer's carries its line's number), did not instrument the class in {@code classFile}, the bytes it was
   * given. Marks the pair and queues it; a pair already reported in this JVM is ignored. {@code failure} is what
   * the transform threw, or null.
   */
  public static void miss(HookExpectation expectation, String unit, byte[] classFile, ProtectionDomain domain,
      String reason, Throwable failure) {
    Candidate now = null;
    HookMissSink target = null;
    boolean startWorker = false;
    synchronized (LOCK) {
      if (table == null || sink == null || !SEEN.add(expectation)) {
        return;
      }
      Candidate candidate = new Candidate(expectation, unit, classFile, domain, reason,
          failure == null ? null : failure.getClass().getName());
      if (inline) {
        now = candidate;
        target = sink;
      } else {
        PENDING.add(candidate);
        if (!draining) {
          draining = true;
          startWorker = true;
        }
      }
    }
    if (now != null) {
      process(now, target);
    } else if (startWorker) {
      startWorker();
    }
  }

  private static void startWorker() {
    try {
      Thread worker = new Thread(new Drain(), "ohmyrasp-hook-miss");
      worker.setDaemon(true);
      worker.setContextClassLoader(null);
      worker.start();
    } catch (Throwable failure) {
      synchronized (LOCK) {
        draining = false;
        PENDING.clear();
      }
    }
  }

  /** The worker: writes what is queued, then ends. The next miss starts another. */
  private static final class Drain implements Runnable {
    @Override
    public void run() {
      while (true) {
        Candidate next;
        HookMissSink target;
        synchronized (LOCK) {
          if (PENDING.isEmpty() || sink == null) {
            PENDING.clear();
            draining = false;
            return;
          }
          next = PENDING.remove(0);
          target = sink;
        }
        try {
          process(next, target);
        } catch (Throwable dropped) {
          // A diagnostic never disturbs the application: the line is lost, the worker goes on.
        }
      }
    }
  }

  /** One queued miss: what the class-loading thread kept, to be read later. */
  private static final class Candidate {
    final HookExpectation expectation;
    final String unit;
    final byte[] classFile;
    final ProtectionDomain domain;
    final String reason;
    final String exception;

    Candidate(HookExpectation expectation, String unit, byte[] classFile, ProtectionDomain domain, String reason,
        String exception) {
      this.expectation = expectation;
      this.unit = unit;
      this.classFile = classFile;
      this.domain = domain;
      this.reason = reason;
      this.exception = exception;
    }
  }

  static void process(Candidate candidate, HookMissSink target) {
    HookExpectation expectation = candidate.expectation;
    List<String> found = methodsNamed(candidate.classFile, expectation);
    if (expectation.absentIsVersionGap && found != null && found.isEmpty() && !TRANSFORM_FAILED.equals(candidate.reason)) {
      return; // a release before the hooked code existed: see HookExpectation.absentIsVersionGap
    }
    boolean last;
    synchronized (LOCK) {
      if (written < LIMIT) {
        written++;
        last = false;
      } else if (!suppressed) {
        suppressed = true;
        last = true;
      } else {
        return;
      }
    }
    if (last) {
      target.write("hook_miss_suppressed", "\"limit\":" + LIMIT + ",\"message\":"
          + quote("More hooks did not apply to the classes they were meant for; further hook-miss lines in this JVM are suppressed."));
      return;
    }
    target.write("hook_miss", fields(candidate, found, origin(candidate.domain, target)));
  }

  /** The methods of the class whose names the unit looks for, as name and descriptor; null when ASM cannot read it. */
  static List<String> methodsNamed(byte[] classFile, final HookExpectation expectation) {
    if (classFile == null) {
      return null;
    }
    final List<String> found = new ArrayList<String>();
    try {
      new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
          if (expectation.looksFor(name)) {
            found.add(name + descriptor);
          }
          return null;
        }
      }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } catch (RuntimeException unreadable) {
      return null;
    }
    return found;
  }

  /** Where a class came from: its code source location, the file name, and the JAR's Implementation-Version. */
  static final class Origin {
    String path;
    String name;
    String version;
  }

  static Origin origin(ProtectionDomain domain, HookMissSink target) {
    CodeSource source = domain == null ? null : domain.getCodeSource();
    URL location = source == null ? null : source.getLocation();
    if (location == null) {
      return null;
    }
    Origin origin = new Origin();
    File file = null;
    if ("file".equals(location.getProtocol())) {
      try {
        file = new File(location.toURI());
      } catch (URISyntaxException | IllegalArgumentException e) {
        file = new File(location.getPath());
      }
      origin.path = file.getPath();
    } else {
      origin.path = location.toString();
    }
    origin.name = lastSegment(origin.path);
    if (file != null && file.getName().endsWith(".jar")) {
      boolean ownIo = target.enterOwnIo();
      try {
        if (file.isFile()) {
          JarFile jar = new JarFile(file, false);
          try {
            Manifest manifest = jar.getManifest();
            if (manifest != null) {
              origin.version = manifest.getMainAttributes().getValue("Implementation-Version");
            }
          } finally {
            jar.close();
          }
        }
      } catch (IOException | RuntimeException unreadable) {
        // No version: the line still names the file.
      } finally {
        target.exitOwnIo(ownIo);
      }
    }
    return origin;
  }

  /** The last path segment of a location: {@code x.jar} of {@code jar:file:/app.jar!/BOOT-INF/lib/x.jar!/}. */
  static String lastSegment(String path) {
    String trimmed = path;
    while (trimmed.endsWith("/") || trimmed.endsWith("!") || trimmed.endsWith("\\")) {
      trimmed = trimmed.substring(0, trimmed.length() - 1);
    }
    int slash = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
    return trimmed.substring(slash + 1);
  }

  static String fields(Candidate candidate, List<String> found, Origin origin) {
    HookExpectation expectation = candidate.expectation;
    String className = expectation.className.replace('/', '.');
    StringBuilder out = new StringBuilder(512);
    out.append("\"unit\":").append(quote(candidate.unit));
    out.append(",\"class\":").append(quote(className));
    out.append(",\"reason\":").append(quote(candidate.reason));
    if (candidate.exception != null) {
      out.append(",\"exception\":").append(quote(candidate.exception));
    }
    out.append(",\"looked_for\":");
    list(out, expectation.methods);
    out.append(",\"found\":");
    list(out, found == null ? new String[0] : found.toArray(new String[0]));
    if (origin != null) {
      out.append(",\"code_source\":").append(quote(origin.name));
      out.append(",\"code_source_path\":").append(quote(origin.path));
      if (origin.version != null) {
        out.append(",\"implementation_version\":").append(quote(origin.version));
      }
    }
    out.append(",\"message\":").append(quote("Hook " + candidate.unit + " did not apply to " + className
        + ": none of the methods it looks for was instrumented, so its protection is off for this class."
        + " Report the library and its version (code_source, implementation_version)."));
    return out.toString();
  }

  private static void list(StringBuilder out, String[] values) {
    out.append('[');
    int shown = Math.min(values.length, MAX_LISTED);
    for (int i = 0; i < shown; i++) {
      if (i > 0) {
        out.append(',');
      }
      out.append(quote(values[i]));
    }
    if (values.length > shown) {
      out.append(',').append(quote("... " + (values.length - shown) + " more"));
    }
    out.append(']');
  }

  /** A JSON string, cut to {@link #MAX_TEXT} characters. */
  static String quote(String value) {
    String text = value == null ? "" : value;
    if (text.length() > MAX_TEXT) {
      text = text.substring(0, MAX_TEXT);
    }
    StringBuilder out = new StringBuilder(text.length() + 2);
    out.append('"');
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      switch (ch) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (ch < 0x20) {
            String hex = Integer.toHexString(ch);
            out.append("\\u");
            for (int pad = hex.length(); pad < 4; pad++) {
              out.append('0');
            }
            out.append(hex);
          } else {
            out.append(ch);
          }
      }
    }
    return out.append('"').toString();
  }
}
