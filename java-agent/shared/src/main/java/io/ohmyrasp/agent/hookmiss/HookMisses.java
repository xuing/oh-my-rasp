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
 * class-loading thread, where it only marks the pair, queues it and wakes the worker: no I/O, no formatting, no
 * thread created, no class of the agent loaded for the first time (on a backport line every class here is
 * preloaded). The worker thread is created once per start, on the start's own thread, when the start commits
 * ({@link #release}; {@link #start} for a report that is not held), and waits for work from then on: it lists the
 * class's methods with the names the unit looks for, reads the {@code Implementation-Version} of the JAR the class
 * came from, and writes the line through the line's {@link HookMissSink}. Anything the worker throws is dropped
 * with its line.
 *
 * <p>Each start and each {@link #stop} begins a new generation. A worker serves one generation: when the report is
 * stopped or started again it ends without taking more work, and a line it is still building is dropped before it
 * reaches the sink, so a stopped report writes nothing more. At JVM exit the event writers call {@link #awaitIdle}
 * before they drain their own queues, so a line in progress gets a bounded time to reach them.
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
  // The current generation: each start and each stop begins a new one, and a worker serves only its own.
  private static int generation;
  // The worker of the current generation, once started; null before release() of a held report and after stop().
  private static Thread worker;
  // Whether the worker is building or writing a line it took from PENDING.
  private static boolean busy;
  // Misses are queued but the worker does not start until release(): a start that can still fail holds the report.
  private static boolean held;
  private static int written;
  private static boolean suppressed;

  private HookMisses() {}

  /**
   * Turns the report on, with the line's table and writer, and starts its worker on the calling thread. For a report
   * that is not held: tests and tools. A line's entry class uses {@link #startHeld} and {@link #release}.
   */
  public static void start(HookExpectations expectations, HookMissSink target) {
    start(expectations, target, false);
  }

  /**
   * As {@link #start(HookExpectations, HookMissSink)}; with {@code writeInline} each line is written on the thread
   * that reports the miss and what the writer throws reaches that thread, for tests and the hook-targets probe.
   */
  public static void start(HookExpectations expectations, HookMissSink target, boolean writeInline) {
    start(expectations, target, writeInline, false);
  }

  /**
   * As {@link #start(HookExpectations, HookMissSink)}, for a start that can still fail after its transformer is
   * added: misses are marked and queued as usual, but no worker thread exists, and nothing is written, until
   * {@link #release}. The start calls {@link #release} once it has committed, on its own thread, and {@link #stop}
   * when it fails, which drops what was queued: a failed start leaves no thread and writes no line.
   */
  public static void startHeld(HookExpectations expectations, HookMissSink target) {
    start(expectations, target, false, true);
  }

  private static void start(HookExpectations expectations, HookMissSink target, boolean writeInline, boolean hold) {
    Thread previous;
    int current;
    synchronized (LOCK) {
      previous = worker;
      worker = null;
      current = ++generation;
      LOCK.notifyAll();
      SEEN.clear();
      PENDING.clear();
      written = 0;
      suppressed = false;
      inline = writeInline;
      held = hold;
      sink = target;
      table = expectations;
    }
    if (previous != null) {
      previous.interrupt();
    }
    if (!hold && !writeInline) {
      startWorker(current);
    }
  }

  /**
   * Ends the hold of {@link #startHeld}: the start has committed. Creates the worker here, on the start's thread,
   * which writes what was queued during the start and waits for later misses. Never throws: a worker that cannot be
   * created turns the report off.
   */
  public static void release() {
    int current;
    synchronized (LOCK) {
      if (!held) {
        return;
      }
      held = false;
      if (sink == null) {
        return;
      }
      current = generation;
    }
    startWorker(current);
  }

  /**
   * Turns the report off: no miss is taken from now on, what is queued is dropped, the worker ends (it is waited for
   * at most {@code STOP_JOIN_MILLIS}) and a line it was building is not written. A worker stuck in its sink's I/O is
   * not waited for: it writes nothing more once that call returns.
   */
  public static void stop() {
    Thread previous;
    synchronized (LOCK) {
      table = null;
      sink = null;
      held = false;
      PENDING.clear();
      generation++;
      previous = worker;
      worker = null;
      LOCK.notifyAll();
    }
    if (previous != null && previous != Thread.currentThread()) {
      boolean interrupted = Thread.interrupted();
      try {
        previous.interrupt();
        previous.join(STOP_JOIN_MILLIS);
      } catch (InterruptedException e) {
        interrupted = true;
      } finally {
        if (interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  /** How long {@link #stop} waits for the worker to end. */
  static final long STOP_JOIN_MILLIS = 1000;

  /**
   * Waits at most {@code millis} for the worker to write what is queued and the line it is building, for a JVM that
   * is exiting: the event writer's shutdown hook calls it before it drains its own queue. Returns at once when the
   * report is off, held (nothing of a start that has not committed is written) or has no worker.
   *
   * @return whether nothing was left
   */
  public static boolean awaitIdle(long millis) {
    long deadline = System.nanoTime() + millis * 1000000L;
    synchronized (LOCK) {
      while (worker != null && !held && sink != null && (busy || !PENDING.isEmpty())) {
        long left = deadline - System.nanoTime();
        if (left <= 0) {
          return false;
        }
        try {
          LOCK.wait(Math.max(1L, left / 1000000L));
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return false;
        }
      }
      return true;
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
        // Queued for the worker, which exists once the start committed; never a thread created here.
        PENDING.add(candidate);
        LOCK.notifyAll();
      }
    }
    if (now != null) {
      process(now, target);
    }
  }

  /**
   * Creates and starts the worker of {@code current}, on the calling thread (a start's, never a class-loading
   * thread's): a daemon with no context loader that, where the JDK allows it (9 and later), inherits no
   * inheritable thread-local, so no application {@code childValue} runs and no application value is kept alive by
   * it. When that fails, or the generation has moved on meanwhile, the report is turned off or left as it is.
   */
  private static void startWorker(int current) {
    Thread created;
    try {
      created = newThread(new Drain(current), "ohmyrasp-hook-miss");
      created.setDaemon(true);
      created.setContextClassLoader(null);
    } catch (Throwable failure) {
      turnOff(current);
      return;
    }
    synchronized (LOCK) {
      if (current != generation || worker != null) {
        return;
      }
      worker = created;
    }
    try {
      created.start();
    } catch (Throwable failure) {
      turnOff(current);
    }
  }

  private static void turnOff(int current) {
    synchronized (LOCK) {
      if (current == generation) {
        table = null;
        sink = null;
        worker = null;
        PENDING.clear();
        generation++;
        LOCK.notifyAll();
      }
    }
  }

  /** A thread that does not inherit inheritable thread-locals, on a JDK that has the constructor for it (9+). */
  private static Thread newThread(Runnable task, String name) {
    try {
      java.lang.reflect.Constructor<Thread> noInheritance = Thread.class.getConstructor(
          ThreadGroup.class, Runnable.class, String.class, long.class, boolean.class);
      return noInheritance.newInstance(null, task, name, Long.valueOf(0L), Boolean.FALSE);
    } catch (NoSuchMethodException javaEight) {
      return new Thread(task, name);
    } catch (ReflectiveOperationException | RuntimeException unavailable) {
      return new Thread(task, name);
    }
  }

  /** The worker of one generation: waits for misses and writes them, until its generation ends. */
  private static final class Drain implements Runnable {
    private final int served;

    Drain(int served) {
      this.served = served;
    }

    @Override
    public void run() {
      while (true) {
        Candidate next;
        HookMissSink target;
        synchronized (LOCK) {
          while (served == generation && PENDING.isEmpty()) {
            try {
              LOCK.wait();
            } catch (InterruptedException interrupted) {
              // stop() or a new start: the generation check below decides.
              if (served != generation) {
                return;
              }
            }
          }
          if (served != generation || sink == null) {
            return;
          }
          next = PENDING.remove(0);
          target = new Served(served, sink);
          busy = true;
        }
        try {
          process(next, target);
        } catch (Throwable dropped) {
          // A diagnostic never disturbs the application: the line is lost, the worker goes on.
        } finally {
          synchronized (LOCK) {
            busy = false;
            LOCK.notifyAll();
          }
        }
      }
    }
  }

  /** The sink of one generation: a line is written only while that generation is still the current one. */
  private static final class Served implements HookMissSink {
    private final int served;
    private final HookMissSink target;

    Served(int served, HookMissSink target) {
      this.served = served;
      this.target = target;
    }

    @Override
    public void write(String diagnostic, String fields) {
      synchronized (LOCK) {
        if (served != generation) {
          return;
        }
      }
      target.write(diagnostic, fields);
    }

    @Override
    public boolean enterOwnIo() {
      return target.enterOwnIo();
    }

    @Override
    public void exitOwnIo(boolean entered) {
      target.exitOwnIo(entered);
    }
  }

  /** The worker thread while there is one. Tests only. */
  static Thread workerThread() {
    synchronized (LOCK) {
      return worker;
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
