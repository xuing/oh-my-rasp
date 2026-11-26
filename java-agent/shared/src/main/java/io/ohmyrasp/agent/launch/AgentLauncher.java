package io.ohmyrasp.agent.launch;

import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;

/**
 * The Premain-Class and Agent-Class of every OhMyRASP agent JAR. It picks the agent line that fits the
 * running Java version and starts it, and it never lets the JVM stop because of the agent: a JAR that
 * holds no fitting line, a second OhMyRASP JAR in the same JVM and a line that throws while starting
 * each leave one JSON line on standard error and return.
 *
 * <p>This class uses nothing but {@code java.*} and loads no other class of ours before it has chosen a
 * line, so it runs on every Java version from 8 on. It is compiled for Java 8 and written without
 * lambdas or method references.
 *
 * <p>The JVM loads a Premain-Class by name through the system class loader, so when two of our JARs are
 * attached, both premain calls run whichever copy of this class the system class loader found first.
 * This class therefore cannot know which JAR it was attached as. It looks the entry classes up through
 * the system class loader, which sees every attached JAR and is the loader the chosen entry class is then
 * loaded with.
 */
public final class AgentLauncher {
  /**
   * Set to the started line's name before the line starts. A system property is the one place two
   * launchers in one JVM can both see without sharing a class: a second JAR's launcher may be a different
   * copy of this class, or the same one, depending on the class path order.
   */
  static final String ACTIVE_PROPERTY = "ohmyrasp.agent.active";

  /** Candidate lines, in the order they are preferred. */
  static final String[] LINES = {"primary", "java17", "java11", "java8"};

  static final String[] ENTRY_CLASSES = {
    "io.ohmyrasp.agent.OhMyRaspAgent",
    "io.ohmyrasp.agent.java17.OhMyRaspJava17Agent",
    "io.ohmyrasp.agent.java11.OhMyRaspJava11Agent",
    "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent"
  };

  /** The lowest Java feature version each line runs on. */
  static final int[] MIN_VERSION = {21, 17, 11, 8};

  /** The highest Java feature version each line runs on. The Java 8 line uses JDK 8 internals. */
  static final int[] MAX_VERSION = {Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE, 8};

  private AgentLauncher() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    launch("premain", agentArgs, instrumentation);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    launch("agentmain", agentArgs, instrumentation);
  }

  private static void launch(String method, String agentArgs, Instrumentation instrumentation) {
    PrintStream err = System.err;
    try {
      launch(method, agentArgs, instrumentation, ClassLoader.getSystemClassLoader(), ENTRY_CLASSES, err);
    } catch (Throwable failure) {
      // Reached only when the launcher itself fails, for example when a security manager denies a property.
      report(err, startFailed("none", failure));
    }
  }

  /**
   * Chooses and starts a line. Package-private so tests can pass their own loader and entry classes.
   *
   * @return the started line's name, or null when no line was started
   */
  static String launch(
      String method,
      String agentArgs,
      Instrumentation instrumentation,
      ClassLoader loader,
      String[] entryClasses,
      PrintStream err) {
    String javaVersion = System.getProperty("java.version", "unknown");
    int feature = featureVersion(System.getProperty("java.specification.version"));
    boolean[] available = new boolean[entryClasses.length];
    for (int i = 0; i < entryClasses.length; i++) {
      available[i] = loader.getResource(entryClasses[i].replace('.', '/').concat(".class")) != null;
    }
    int chosen = choose(feature, available);
    if (chosen < 0) {
      report(err, "{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\","
          + "\"java_version\":\"" + json(javaVersion) + "\","
          + "\"lines\":\"" + json(lineList(available)) + "\"}");
      return null;
    }
    String line = LINES[chosen];
    String active = claim(line);
    if (active != null) {
      report(err, "{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"already-active\","
          + "\"java_version\":\"" + json(javaVersion) + "\","
          + "\"active_line\":\"" + json(active) + "\"}");
      return null;
    }
    try {
      Class<?> entry = Class.forName(entryClasses[chosen], true, loader);
      Method start = entry.getMethod(method, String.class, Instrumentation.class);
      start.invoke(null, agentArgs, instrumentation);
      return line;
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause() == null ? e : e.getCause();
      report(err, startFailed(line, cause));
    } catch (Throwable failure) {
      report(err, startFailed(line, failure));
    }
    return null;
  }

  /**
   * Records {@code line} as the active agent unless one is recorded already.
   *
   * @return the line recorded earlier, or null when this call recorded {@code line}
   */
  private static String claim(String line) {
    // The monitor makes check-and-set atomic between two launchers; it is released before the line
    // starts, so a line thread that reads a system property never waits on it.
    Properties properties = System.getProperties();
    synchronized (properties) {
      String active = properties.getProperty(ACTIVE_PROPERTY);
      if (active != null) {
        return active;
      }
      properties.setProperty(ACTIVE_PROPERTY, line);
      return null;
    }
  }

  /**
   * The Java feature version from {@code java.specification.version}: "1.8" is 8, "17" is 17. Returns
   * -1 for a missing or unreadable value.
   */
  static int featureVersion(String specification) {
    if (specification == null) {
      return -1;
    }
    String value = specification.trim();
    if (value.startsWith("1.")) {
      value = value.substring(2);
    }
    int end = 0;
    while (end < value.length() && end < 9 && Character.isDigit(value.charAt(end))) {
      end++;
    }
    if (end == 0) {
      return -1;
    }
    return Integer.parseInt(value.substring(0, end));
  }

  /** The index of the first available line whose version range holds {@code feature}, or -1. */
  static int choose(int feature, boolean[] available) {
    for (int i = 0; i < available.length && i < LINES.length; i++) {
      if (available[i] && feature >= MIN_VERSION[i] && feature <= MAX_VERSION[i]) {
        return i;
      }
    }
    return -1;
  }

  private static String lineList(boolean[] available) {
    StringBuilder names = new StringBuilder();
    for (int i = 0; i < available.length && i < LINES.length; i++) {
      if (available[i]) {
        if (names.length() > 0) {
          names.append(',');
        }
        names.append(LINES[i]);
      }
    }
    return names.toString();
  }

  private static String startFailed(String line, Throwable failure) {
    return "{\"event\":\"ohmyrasp-agent-start-failed\","
        + "\"line\":\"" + json(line) + "\","
        + "\"java_version\":\"" + json(System.getProperty("java.version", "unknown")) + "\","
        + "\"exception\":\"" + json(failure.getClass().getName()) + "\","
        + "\"message\":\"" + json(String.valueOf(failure.getMessage())) + "\"}";
  }

  private static void report(PrintStream err, String line) {
    try {
      err.println(line);
      err.flush();
    } catch (Throwable ignored) {
      // Nothing else to tell; the JVM must keep starting.
    }
  }

  static String json(String value) {
    StringBuilder builder = new StringBuilder(value.length() + 16);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"':
          builder.append("\\\"");
          break;
        case '\\':
          builder.append("\\\\");
          break;
        case '\b':
          builder.append("\\b");
          break;
        case '\f':
          builder.append("\\f");
          break;
        case '\n':
          builder.append("\\n");
          break;
        case '\r':
          builder.append("\\r");
          break;
        case '\t':
          builder.append("\\t");
          break;
        default:
          if (ch < 0x20) {
            String hex = Integer.toHexString(ch);
            builder.append("\\u");
            for (int pad = hex.length(); pad < 4; pad++) {
              builder.append('0');
            }
            builder.append(hex);
          } else {
            builder.append(ch);
          }
      }
    }
    return builder.toString();
  }
}
