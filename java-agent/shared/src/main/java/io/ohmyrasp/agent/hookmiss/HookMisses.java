package io.ohmyrasp.agent.hookmiss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The run-time hook-miss report: one diagnostic line per (hook unit, class) per JVM when a unit that is meant to
 * instrument a loaded library class did not, so a library release that renamed or changed a hooked method is
 * reported where it runs instead of passing silently.
 *
 * <p>What counts as a miss is decided by the transformers, after their own work is done: a class of the
 * {@link HookExpectations} table that the unit selects went through the unit and none of the methods the unit is
 * recorded instrumenting there calls the agent methods the unit is recorded adding ({@link AgentCalls}). They call
 * {@link #miss} on the class-loading thread, where it copies a few bounded strings out of the class and its code
 * source (the methods with the names the unit looks for, the location), marks the pair, queues it and wakes the
 * worker: no I/O, no thread created, no lock the writer holds across I/O, no class of the agent loaded for the
 * first time (on a backport line every class here is preloaded), and nothing kept that refers to the class's
 * loader. The worker thread is created once per start, on the start's own thread, when the start commits
 * ({@link #release}; {@link #start} for a report that is not held), and waits for work from then on: it reads the
 * {@code Implementation-Version} of a plain JAR (marked as the agent's own I/O, bounded by the JAR's and the
 * manifest's size) and writes the line through the line's {@link HookMissSink}, which has its own bounded path and
 * never uses the detections' queue. Anything the worker's sink throws drops its line and is counted
 * ({@link #sinkFailures}).
 *
 * <p>Each start and each {@link #stop} begins a new generation. A worker serves one generation: when the report is
 * stopped or started again it ends without taking more work, and a line it is still building is dropped before it
 * reaches the sink, so a stopped report writes nothing more. At JVM exit the event writers call {@link #awaitIdle}
 * before they drain their own queues, so a line in progress gets a bounded time to reach them.
 *
 * <p>At most {@link #LIMIT} lines per JVM, then one {@code hook_miss_suppressed} line and nothing more, charged when
 * a miss is queued: the table holds a few hundred pairs, a library release that breaks a hook usually breaks one to
 * a few classes, and the cap keeps a JVM that runs many such libraries to a few dozen lines (each a few hundred
 * bytes to about 2 KiB) and the queue to that many small candidates.
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
  private static final AtomicLong SINK_FAILURES = new AtomicLong();

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
      SINK_FAILURES.set(0);
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
   * Whether a miss of {@code expectation} would be kept now: the report is on, the pair has not been reported in
   * this JVM and the limit has not made suppression final. A transformer asks before it reads a class for a
   * verdict, so a pair already reported costs a lookup and no scan.
   */
  public static boolean wants(HookExpectation expectation) {
    synchronized (LOCK) {
      return table != null && sink != null && !SEEN.contains(expectation) && !(written >= LIMIT && suppressed);
    }
  }

  /**
   * On the class-loading thread: {@code unit}, the unit of {@code expectation} under its own name (a backport
   * transformer's carries its line's number), did not instrument the class in {@code classFile}, the bytes it was
   * given. Reads what the line will say from {@code classFile} and {@code domain} now, as a few bounded strings, and
   * keeps neither of them or anything that refers to the class's loader; then marks the pair and queues it. A pair
   * already reported in this JVM is ignored, and so is one the table exempts for this class (see
   * {@link HookExpectation#absentIsVersionGap}), which does not use the pair up, so a broken release loaded after an
   * older exempt one is still reported. {@code failure} is what the transform threw, or null.
   *
   * <p>The first qualifying miss of a (unit, class) pair is the one reported, whichever class loader, library
   * version or retransformation it comes from: the report says that a hook did not apply somewhere in this JVM,
   * and {@code code_source} and {@code implementation_version} say where.
   */
  public static void miss(HookExpectation expectation, String unit, byte[] classFile, ProtectionDomain domain,
      String reason, Throwable failure) {
    if (!wants(expectation)) {
      return;
    }
    Candidate candidate = Candidate.of(expectation, unit, classFile, domain, reason, failure);
    if (candidate == null) {
      return;
    }
    Candidate now = null;
    HookMissSink target = null;
    synchronized (LOCK) {
      if (table == null || sink == null || !SEEN.add(expectation)) {
        return;
      }
      // Charged when queued: what waits is bounded by LIMIT and one suppressed line, whatever the sink does.
      if (written < LIMIT) {
        written++;
      } else if (!suppressed) {
        suppressed = true;
        candidate = Candidate.suppressedLine();
      } else {
        return;
      }
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

  /** How many candidates wait for the worker, for a test of the queue's bound. */
  static int queued() {
    synchronized (LOCK) {
      return PENDING.size();
    }
  }

  /** How many lines the sink failed to take (it threw, on the worker); they were dropped and are not retried. */
  public static long sinkFailures() {
    return SINK_FAILURES.get();
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
          // A diagnostic never disturbs the application: the line is lost and counted, the worker goes on.
          SINK_FAILURES.incrementAndGet();
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

  /**
   * One queued miss: a few bounded strings the class-loading thread copied from the class and its code source. It
   * holds no class file, {@code ProtectionDomain}, {@code Class} or class loader, so a candidate that waits for a
   * stalled worker cannot keep an application's loader, and with at most {@code LIMIT + 1} queued and each text at
   * most {@link #MAX_TEXT} characters, the queue holds a few hundred KiB at most.
   */
  private static final class Candidate {
    /** The pair, from the shipped table; null for the one suppressed line. */
    final HookExpectation expectation;
    final String unit;
    final String reason;
    final String exception;
    /** The methods of the class with a name the unit looks for, at most {@link #MAX_LISTED}. */
    final List<String> found;
    /** How many more there were. */
    final int foundOmitted;
    /** Where the class came from; null when it has no code source. */
    final Origin origin;

    private Candidate(HookExpectation expectation, String unit, String reason, String exception, List<String> found,
        int foundOmitted, Origin origin) {
      this.expectation = expectation;
      this.unit = unit;
      this.reason = reason;
      this.exception = exception;
      this.found = found;
      this.foundOmitted = foundOmitted;
      this.origin = origin;
    }

    static Candidate suppressedLine() {
      return new Candidate(null, null, null, null, null, 0, null);
    }

    /** The candidate for a miss, or null when the pair is exempt for this class. */
    static Candidate of(HookExpectation expectation, String unit, byte[] classFile, ProtectionDomain domain,
        String reason, Throwable failure) {
      Found methods = methodsNamed(classFile, expectation);
      if (expectation.absentIsVersionGap && methods != null && methods.shown.isEmpty()
          && !TRANSFORM_FAILED.equals(reason)) {
        return null; // a release before the hooked code existed: see HookExpectation.absentIsVersionGap
      }
      String exception = failure == null ? null : cut(failure.getClass().getName());
      return new Candidate(expectation, cut(unit), reason, exception,
          methods == null ? new ArrayList<String>(0) : methods.shown, methods == null ? 0 : methods.omitted,
          Origin.of(domain));
    }
  }

  /** The most methods and the omitted count that {@link #methodsNamed} found. */
  static final class Found {
    final List<String> shown = new ArrayList<String>();
    int omitted;
  }

  /**
   * One queued line, on the worker. The line's methods and origin were copied when it was queued; only the
   * manifest of a plain JAR file is read here.
   */
  static void process(Candidate candidate, HookMissSink target) {
    if (candidate.expectation == null) {
      target.write("hook_miss_suppressed", "\"limit\":" + LIMIT + ",\"message\":"
          + quote("More hooks did not apply to the classes they were meant for; further hook-miss lines in this JVM are suppressed."));
      return;
    }
    String version = candidate.origin == null ? null : candidate.origin.version(target);
    target.write("hook_miss", fields(candidate, version));
  }

  /**
   * The methods of the class whose names the unit looks for, as name and descriptor, at most {@link #MAX_LISTED}
   * of them and a count of the others; null when ASM cannot read the class or it is larger than
   * {@link AgentCalls#MAX_CLASS_BYTES}.
   */
  static Found methodsNamed(byte[] classFile, final HookExpectation expectation) {
    if (classFile == null || classFile.length > AgentCalls.MAX_CLASS_BYTES) {
      return null;
    }
    final Found found = new Found();
    try {
      new ClassReader(classFile).accept(new ClassVisitor(Opcodes.ASM9) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
          if (expectation.looksFor(name)) {
            if (found.shown.size() < MAX_LISTED) {
              found.shown.add(cut(name + descriptor));
            } else {
              found.omitted++;
            }
          }
          return null;
        }
      }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } catch (RuntimeException unreadable) {
      return null;
    }
    return found;
  }

  /** The largest JAR file whose manifest is read, in bytes; a larger one has no {@code implementation_version}. */
  static final long MAX_JAR_BYTES = 256L << 20;
  /** The largest manifest read, in bytes. */
  static final int MAX_MANIFEST_BYTES = 64 << 10;

  /**
   * Where a class came from, as plain strings: its code source location (no query, no fragment, no credentials)
   * and the file name. Taken from the location's own fields on the class-loading thread, so a custom URL handler
   * is never asked to render it.
   */
  static final class Origin {
    final String path;
    final String name;
    /** The file of a plain {@code file:} location, else null. */
    final File file;

    private Origin(String path, boolean plainFile) {
      this.path = cut(path);
      this.name = cut(lastSegment(path));
      this.file = plainFile ? new File(path) : null;
    }

    static Origin of(ProtectionDomain domain) {
      try {
        CodeSource source = domain == null ? null : domain.getCodeSource();
        URL location = source == null ? null : source.getLocation();
        if (location == null) {
          return null;
        }
        String protocol = location.getProtocol();
        String path = location.getPath();
        if (path == null) {
          path = "";
        }
        if ("file".equals(protocol)) {
          return new Origin(filePath(path), true);
        }
        String host = location.getHost();
        String where = host == null || host.isEmpty() ? "" : "//" + host + (location.getPort() < 0 ? "" : ":" + location.getPort());
        return new Origin(withoutCredentials(protocol + ":" + where + path), false);
      } catch (Throwable unreadable) {
        return null;
      }
    }

    /**
     * The JAR's {@code Implementation-Version}, read on the worker with the agent's own-I/O mark set before the first
     * file call. Null when the location is not a plain {@code .jar} file, the JAR is larger than
     * {@link #MAX_JAR_BYTES}, its manifest is larger than {@link #MAX_MANIFEST_BYTES} or anything fails: the line
     * still names the file. The read is bounded by those sizes, not by a clock.
     */
    String version(HookMissSink target) {
      if (file == null || !file.getName().endsWith(".jar")) {
        return null;
      }
      boolean ownIo = target.enterOwnIo();
      try {
        if (!file.isFile() || file.length() > MAX_JAR_BYTES) {
          return null;
        }
        JarFile jar = new JarFile(file, false);
        try {
          ZipEntry entry = jar.getEntry("META-INF/MANIFEST.MF");
          if (entry == null) {
            return null;
          }
          byte[] manifest = readAtMost(jar.getInputStream(entry), MAX_MANIFEST_BYTES);
          return manifest == null ? null
              : new Manifest(new ByteArrayInputStream(manifest)).getMainAttributes().getValue("Implementation-Version");
        } finally {
          jar.close();
        }
      } catch (IOException | RuntimeException unreadable) {
        return null; // No version: the line still names the file.
      } finally {
        target.exitOwnIo(ownIo);
      }
    }
  }

  /** All of {@code in}, closed, or null when it is longer than {@code limit} bytes. */
  private static byte[] readAtMost(InputStream in, int limit) throws IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      for (int n = in.read(buffer); n > 0; n = in.read(buffer)) {
        out.write(buffer, 0, n);
        if (out.size() > limit) {
          return null;
        }
      }
      return out.toByteArray();
    } finally {
      in.close();
    }
  }

  /** The path of a {@code file:} URL, percent-decoded as UTF-8 and, on Windows, without the slash before the drive. */
  static String filePath(String urlPath) {
    String path = urlPath;
    if (path.indexOf('%') >= 0) {
      ByteArrayOutputStream out = new ByteArrayOutputStream(path.length());
      int i = 0;
      while (i < path.length()) {
        char ch = path.charAt(i);
        int high = ch == '%' && i + 2 < path.length() ? Character.digit(path.charAt(i + 1), 16) : -1;
        int low = high >= 0 ? Character.digit(path.charAt(i + 2), 16) : -1;
        if (low >= 0) {
          out.write(high * 16 + low);
          i += 3;
        } else {
          int length = Character.isHighSurrogate(ch) && i + 1 < path.length() ? 2 : 1;
          byte[] bytes = path.substring(i, i + length).getBytes(StandardCharsets.UTF_8);
          out.write(bytes, 0, bytes.length);
          i += length;
        }
      }
      path = new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
    if (File.separatorChar == '\\' && path.length() > 2 && path.charAt(0) == '/' && path.charAt(2) == ':') {
      path = path.substring(1);
    }
    return new File(path).getPath();
  }

  /** {@code text} without the {@code user:password@} of any {@code scheme://user:password@host} in it. */
  static String withoutCredentials(String text) {
    StringBuilder out = new StringBuilder(text.length());
    int from = 0;
    while (true) {
      int scheme = text.indexOf("://", from);
      if (scheme < 0) {
        break;
      }
      int start = scheme + 3;
      int end = start;
      while (end < text.length() && text.charAt(end) != '/' && text.charAt(end) != '!') {
        end++;
      }
      int at = text.lastIndexOf('@', end - 1);
      out.append(text, from, start);
      from = at >= start && at < end ? at + 1 : start;
    }
    return out.append(text, from, text.length()).toString();
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

  static String fields(Candidate candidate, String version) {
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
    int lookedOmitted = list(out, expectation.methods, expectation.methods.length);
    out.append(",\"found\":");
    list(out, candidate.found.toArray(new String[0]), candidate.found.size());
    if (lookedOmitted > 0) {
      out.append(",\"looked_for_omitted\":").append(lookedOmitted);
    }
    if (candidate.foundOmitted > 0) {
      out.append(",\"found_omitted\":").append(candidate.foundOmitted);
    }
    Origin origin = candidate.origin;
    if (origin != null) {
      out.append(",\"code_source\":").append(quote(origin.name));
      out.append(",\"code_source_path\":").append(quote(origin.path));
      if (version != null) {
        out.append(",\"implementation_version\":").append(quote(version));
      }
    }
    out.append(",\"message\":").append(quote("Hook " + candidate.unit + " did not apply to " + className
        + ": none of the methods it looks for was instrumented, so its protection is off for this class."
        + " Report the library and its version (code_source, implementation_version)."));
    return out.toString();
  }

  /** Writes at most {@link #MAX_LISTED} of {@code values} as a JSON array; returns how many it left out. */
  private static int list(StringBuilder out, String[] values, int count) {
    out.append('[');
    int shown = Math.min(count, MAX_LISTED);
    for (int i = 0; i < shown; i++) {
      if (i > 0) {
        out.append(',');
      }
      out.append(quote(values[i]));
    }
    out.append(']');
    return count - shown;
  }

  /** {@code text} cut to {@link #MAX_TEXT} characters, never between the two halves of a surrogate pair. */
  static String cut(String text) {
    if (text == null) {
      return "";
    }
    if (text.length() <= MAX_TEXT) {
      return text;
    }
    int end = MAX_TEXT;
    if (Character.isHighSurrogate(text.charAt(end - 1))) {
      end--;
    }
    return text.substring(0, end);
  }

  /**
   * A JSON string, cut to {@link #MAX_TEXT} characters on a code point boundary, with every unpaired surrogate
   * replaced by U+FFFD so the line is valid UTF-8 whatever the text held.
   */
  static String quote(String value) {
    String text = cut(value);
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
          } else if (Character.isHighSurrogate(ch)) {
            if (i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) {
              out.append(ch).append(text.charAt(++i));
            } else {
              out.append('\uFFFD');
            }
          } else if (Character.isLowSurrogate(ch)) {
            out.append('\uFFFD');
          } else {
            out.append(ch);
          }
      }
    }
    return out.append('"').toString();
  }
}
