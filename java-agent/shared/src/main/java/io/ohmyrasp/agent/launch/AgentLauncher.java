package io.ohmyrasp.agent.launch;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.Properties;
import java.util.jar.JarFile;

/**
 * Starts the agent line that fits the running Java from the JAR an entry class came from, and never
 * lets the JVM stop because of the agent. Each kind of agent JAR has its own entry class (see
 * {@link UniversalEntry}), which passes itself here. A JAR that holds no fitting line, a JAR that
 * finds an agent already started or failed in this JVM, and a line that throws while starting each
 * leave one JSON line on standard error and return.
 *
 * <p>This class uses nothing but {@code java.*} and loads no class of ours before it has chosen a
 * line, so it runs on every Java version from 8 on. It is compiled for Java 8 and written without
 * lambdas or method references.
 */
public final class AgentLauncher {
  /**
   * One start per JVM, across premain and agentmain and across our JARs: {@code starting}, then
   * {@code installed:<line>} or {@code failed:<line>}. A system property is the one place launchers
   * from two JARs can both see without sharing a loaded class.
   */
  static final String STATE_PROPERTY = "ohmyrasp.agent.state";

  /** The installed line, set once the line's entry method returned. */
  static final String LINE_PROPERTY = "ohmyrasp.agent.line";

  /** Candidate lines, in the order they are preferred. */
  static final String[] LINES = {"primary", "java17", "java11", "java8"};

  static final String[] LINE_ENTRY_CLASSES = {
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

  /** Called by an entry class with itself as {@code entry}. Never throws. */
  public static void start(
      String method, String agentArgs, Instrumentation instrumentation, Class<?> entry) {
    PrintStream err = System.err;
    try {
      launch(method, agentArgs, instrumentation, entry, ClassLoader.getSystemClassLoader(),
          LINE_ENTRY_CLASSES, err);
    } catch (Throwable failure) {
      // Reached only when the launcher itself fails, for example on an unreadable agent JAR.
      report(err, "{\"event\":\"ohmyrasp-agent-start-failed\",\"line\":\"none\","
          + "\"protection\":\"inactive\"," + failureFields(failure) + "}");
    }
  }

  /**
   * Chooses and starts a line. Package-private so tests can pass their own loader and line entries.
   *
   * @return the started line's name, or null when no line was started
   */
  static String launch(
      String method,
      String agentArgs,
      Instrumentation instrumentation,
      Class<?> entry,
      ClassLoader loader,
      String[] lineEntries,
      PrintStream err)
      throws IOException {
    String javaVersion = json(System.getProperty("java.version", "unknown"));
    String state = System.getProperty(STATE_PROPERTY);
    if (state != null) {
      report(err, skipped(state, javaVersion));
      return null;
    }
    File artifact = artifactOf(entry);
    boolean[] available = new boolean[lineEntries.length];
    for (int i = 0; i < lineEntries.length; i++) {
      available[i] = artifact != null && holds(artifact, lineEntries[i]);
    }
    int chosen = choose(featureVersion(System.getProperty("java.specification.version")), available);
    if (chosen < 0) {
      report(err, "{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\","
          + "\"java_version\":\"" + javaVersion + "\","
          + "\"lines\":\"" + json(lineList(available)) + "\","
          + "\"jar\":\"" + json(artifact == null ? "unknown" : artifact.getName()) + "\"}");
      return null;
    }
    String line = LINES[chosen];
    state = claim();
    if (state != null) {
      report(err, skipped(state, javaVersion));
      return null;
    }
    try {
      Class<?> lineEntry = Class.forName(lineEntries[chosen], true, loader);
      Method start = lineEntry.getMethod(method, String.class, Instrumentation.class);
      start.invoke(null, agentArgs, instrumentation);
    } catch (Throwable failure) {
      Throwable cause = failure;
      if (failure instanceof InvocationTargetException && failure.getCause() != null) {
        cause = failure.getCause();
      }
      System.setProperty(STATE_PROPERTY, "failed:" + line);
      report(err, "{\"event\":\"ohmyrasp-agent-start-failed\",\"line\":\"" + json(line) + "\","
          + "\"protection\":\"inactive or incomplete\","
          + "\"java_version\":\"" + javaVersion + "\"," + failureFields(cause) + "}");
      return null;
    }
    System.setProperty(LINE_PROPERTY, line);
    System.setProperty(STATE_PROPERTY, "installed:" + line);
    return line;
  }

  /**
   * Records {@code starting} unless a state is recorded already.
   *
   * @return the state recorded earlier, or null when this call recorded {@code starting}
   */
  private static String claim() {
    // The monitor makes check-and-set atomic between two launchers; it is released before the line
    // starts, so a line thread that reads a system property never waits on it.
    Properties properties = System.getProperties();
    synchronized (properties) {
      String state = properties.getProperty(STATE_PROPERTY);
      if (state != null) {
        return state;
      }
      properties.setProperty(STATE_PROPERTY, "starting");
      return null;
    }
  }

  private static String skipped(String state, String javaVersion) {
    String reason = state.startsWith("failed:") ? "earlier-start-failed" : "already-active";
    return "{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"" + reason + "\","
        + "\"java_version\":\"" + javaVersion + "\","
        + "\"state\":\"" + json(state) + "\"}";
  }

  /**
   * The JAR file or class directory {@code entry} was loaded from, or null when it cannot be told.
   * A class defined by the bootstrap loader (the Java 8 JAR's Boot-Class-Path) records no code
   * source; its class file then names the JAR, since no other kind of agent JAR holds that class.
   */
  static File artifactOf(Class<?> entry) throws MalformedURLException {
    ProtectionDomain domain = entry.getProtectionDomain();
    CodeSource source = domain == null ? null : domain.getCodeSource();
    URL location = source == null ? null : source.getLocation();
    if (location == null) {
      String classFile = entry.getName().replace('.', '/').concat(".class");
      location = containerOf(ClassLoader.getSystemResource(classFile), classFile);
    }
    return location == null ? null : toFile(location);
  }

  /** The JAR or directory URL that holds {@code resource}, named {@code path} inside it. */
  static URL containerOf(URL resource, String path) throws MalformedURLException {
    if (resource == null) {
      return null;
    }
    String text = resource.toString();
    if (text.startsWith("jar:")) {
      int separator = text.indexOf("!/");
      return separator < 0 ? null : new URL(text.substring(4, separator));
    }
    if (text.endsWith(path)) {
      return new URL(text.substring(0, text.length() - path.length()));
    }
    return null;
  }

  private static File toFile(URL location) {
    try {
      return new File(location.toURI());
    } catch (URISyntaxException e) {
      return new File(location.getPath());
    } catch (IllegalArgumentException e) {
      return new File(location.getPath());
    }
  }

  /** Whether the JAR file or class directory holds the class file of {@code className}. */
  static boolean holds(File artifact, String className) throws IOException {
    String path = className.replace('.', '/').concat(".class");
    if (artifact.isDirectory()) {
      return new File(artifact, path).isFile();
    }
    JarFile jar = new JarFile(artifact, false);
    try {
      return jar.getEntry(path) != null;
    } finally {
      jar.close();
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

  private static String failureFields(Throwable failure) {
    return "\"exception\":\"" + json(failure.getClass().getName()) + "\","
        + "\"message\":\"" + json(String.valueOf(failure.getMessage())) + "\"";
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
