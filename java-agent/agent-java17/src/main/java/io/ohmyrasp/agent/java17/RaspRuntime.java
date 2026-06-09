package io.ohmyrasp.agent.java17;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java 17 backport runtime: asynchronous event spool plus control-file-driven
 * detection mode. Mirrors the agent-jdk25 design using only Java 17 APIs.
 *
 * <p>Deliberately self-contained and duplicated per backport module (no shared
 * module), so each backport jar stays independently buildable. Event reporting
 * runs on a background daemon thread so the protected request never blocks on a
 * file write; {@code OHMYRASP_LOG_SYNC=true} reverts to inline writes for
 * deterministic acceptance/CI runs. The detection mode (off/monitor/block) is
 * read from the daemon/operator control file and hot-reloaded by polling.
 */
final class RaspRuntime {
  enum Mode {
    OFF,
    MONITOR,
    BLOCK
  }

  private RaspRuntime() {}

  // ---- detection mode, polled from the control file -----------------------

  private static final Pattern MODE_PATTERN = Pattern.compile("\"mode\"\\s*:\\s*\"([a-zA-Z]+)\"");
  private static final Path CONTROL_PATH = resolveControlPath();
  private static volatile Mode mode; // null = unset -> legacy behavior
  private static volatile long controlMtime = Long.MIN_VALUE;

  static {
    reloadControl();
    Thread poller =
        new Thread(
            new Runnable() {
              public void run() {
                while (true) {
                  try {
                    Thread.sleep(pollMillis());
                    reloadControl();
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                  } catch (RuntimeException ignored) {
                    // never let control polling disturb the application
                  }
                }
              }
            },
            "ohmyrasp-java17-control");
    poller.setDaemon(true);
    poller.start();
  }

  static Mode mode() {
    return mode;
  }

  /** True only when detection is explicitly OFF. */
  static boolean detectionOff() {
    return mode == Mode.OFF;
  }

  /** BLOCK or unset (legacy env flag) permit blocking; MONITOR/OFF do not. */
  static boolean blockingAllowed(boolean legacyEnvFlag) {
    Mode current = mode;
    if (current == Mode.BLOCK) {
      return true;
    }
    if (current == Mode.MONITOR || current == Mode.OFF) {
      return false;
    }
    return legacyEnvFlag;
  }

  private static void reloadControl() {
    try {
      if (CONTROL_PATH == null || !Files.isRegularFile(CONTROL_PATH)) {
        return;
      }
      long mtime = Files.getLastModifiedTime(CONTROL_PATH).toMillis();
      if (mtime == controlMtime) {
        return;
      }
      controlMtime = mtime;
      String text = new String(Files.readAllBytes(CONTROL_PATH), StandardCharsets.UTF_8);
      Matcher matcher = MODE_PATTERN.matcher(text);
      if (matcher.find()) {
        Mode parsed = parseMode(matcher.group(1));
        if (parsed != null) {
          mode = parsed;
        }
      }
    } catch (IOException | RuntimeException ignored) {
      // keep last known good state
    }
  }

  private static Mode parseMode(String token) {
    if (token == null) {
      return null;
    }
    String value = token.trim().toLowerCase(Locale.ROOT);
    if (value.equals("off") || value.equals("disabled") || value.equals("none")) {
      return Mode.OFF;
    }
    if (value.equals("monitor") || value.equals("record") || value.equals("observe") || value.equals("log")) {
      return Mode.MONITOR;
    }
    if (value.equals("block") || value.equals("blocking") || value.equals("protect")) {
      return Mode.BLOCK;
    }
    return null;
  }

  private static Path resolveControlPath() {
    String configured =
        firstNonBlank(System.getProperty("ohmyrasp.control"), System.getenv("OHMYRASP_CONTROL"));
    return Paths.get(configured == null ? "/tmp/ohmyrasp-control.json" : configured);
  }

  private static long pollMillis() {
    String configured =
        firstNonBlank(
            System.getProperty("ohmyrasp.control.poll_ms"), System.getenv("OHMYRASP_CONTROL_POLL_MS"));
    if (configured != null) {
      try {
        return Math.max(200L, Long.parseLong(configured.trim()));
      } catch (NumberFormatException ignored) {
        // fall through
      }
    }
    return 2000L;
  }

  // ---- asynchronous event spool -------------------------------------------

  private static final BlockingQueue<String> QUEUE = new ArrayBlockingQueue<String>(8192);
  private static final AtomicLong DROPPED = new AtomicLong();
  private static final AtomicLong SAMPLE_COUNTER = new AtomicLong();
  private static final boolean SYNC = syncFlag();
  private static final int SAMPLE_RATE = sampleRate();
  private static volatile boolean running = true;
  private static volatile String lastLogPath;

  static {
    Thread writer =
        new Thread(
            new Runnable() {
              public void run() {
                drain();
              }
            },
            "ohmyrasp-java17-writer");
    writer.setDaemon(true);
    writer.start();
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                new Runnable() {
                  public void run() {
                    running = false;
                    flushRemaining();
                  }
                }));
  }

  /** Resolve the spool path the same way the detection writer does. */
  static String resolveLogPath() {
    return firstNonBlank(
        System.getProperty("ohmyrasp.java17.log"),
        System.getProperty("ohmyrasp.log"),
        System.getenv("OHMYRASP_LOG"));
  }

  /** Off the business hot path: enqueue an already-built event line. */
  static void writeEvent(String logPath, String line) {
    if (logPath == null) {
      System.err.println(line);
      return;
    }
    lastLogPath = logPath;
    if (SYNC) {
      appendBatch(logPath, Collections.singletonList(line));
      return;
    }
    if (!QUEUE.offer(line)) {
      DROPPED.incrementAndGet();
    }
  }

  /**
   * Record a sampled measurement of the overhead added to a (usually benign)
   * request as a telemetry line, so the daemon's latency panel reflects real
   * traffic. Suppressed in sync mode to keep acceptance output deterministic.
   */
  static void sampleLatency(long micros) {
    if (SYNC || detectionOff() || micros < 0) {
      return;
    }
    if (SAMPLE_RATE > 1 && SAMPLE_COUNTER.incrementAndGet() % SAMPLE_RATE != 0) {
      return;
    }
    String line =
        "{\"timestamp\":"
            + System.currentTimeMillis()
            + ",\"kind\":\"telemetry\",\"hook\":\"http_request\",\"algorithm\":\"hook_latency\","
            + "\"action\":\"observe\",\"confidence\":0,\"latency_us\":"
            + micros
            + "}";
    writeEvent(resolveLogPath(), line);
  }

  private static void drain() {
    List<String> batch = new ArrayList<String>(64);
    while (running || !QUEUE.isEmpty()) {
      try {
        String first = QUEUE.poll(200, TimeUnit.MILLISECONDS);
        if (first == null) {
          continue;
        }
        batch.clear();
        batch.add(first);
        QUEUE.drainTo(batch, 511);
        String target = lastLogPath;
        if (target != null) {
          appendBatch(target, batch);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (RuntimeException e) {
        System.err.println("[OHMYRASP-JAVA17] event writer error: " + e);
      }
    }
  }

  private static void flushRemaining() {
    List<String> rest = new ArrayList<String>();
    QUEUE.drainTo(rest);
    String target = lastLogPath;
    if (target != null && !rest.isEmpty()) {
      appendBatch(target, rest);
    }
  }

  private static void appendBatch(String logPath, List<String> lines) {
    File target = new File(logPath);
    File parent = target.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      System.err.println("[OHMYRASP-JAVA17] could not create log directory: " + parent);
      return;
    }
    synchronized (RaspRuntime.class) {
      FileWriter writer = null;
      try {
        writer = new FileWriter(target, true);
        String separator = System.lineSeparator();
        for (int i = 0; i < lines.size(); i++) {
          writer.write(lines.get(i));
          writer.write(separator);
        }
      } catch (IOException e) {
        System.err.println("[OHMYRASP-JAVA17] could not write detection event: " + e);
      } finally {
        if (writer != null) {
          try {
            writer.close();
          } catch (IOException ignored) {
            // nothing useful to do during sink protection
          }
        }
      }
    }
  }

  private static boolean syncFlag() {
    String value =
        firstNonBlank(System.getProperty("ohmyrasp.log.sync"), System.getenv("OHMYRASP_LOG_SYNC"));
    if (value == null) {
      return false;
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    return normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("on");
  }

  private static int sampleRate() {
    String value =
        firstNonBlank(System.getProperty("ohmyrasp.latency_sample"), System.getenv("OHMYRASP_LATENCY_SAMPLE"));
    if (value != null) {
      try {
        return Math.max(1, Integer.parseInt(value.trim()));
      } catch (NumberFormatException ignored) {
        // fall through
      }
    }
    return 10;
  }

  private static String firstNonBlank(String first, String second) {
    return firstNonBlank(first, second, null);
  }

  private static String firstNonBlank(String first, String second, String third) {
    if (first != null && first.trim().length() > 0) {
      return first;
    }
    if (second != null && second.trim().length() > 0) {
      return second;
    }
    if (third != null && third.trim().length() > 0) {
      return third;
    }
    return null;
  }
}
