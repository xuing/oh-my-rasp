package io.ohmyrasp.agent.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.instrument.Instrumentation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AgentLauncherTest {
  private static final String PRIMARY = "primary";
  private static final String MISSING = "io.ohmyrasp.agent.launch.NoSuchEntry";
  private static final boolean[] ALL = {true, true, true, true};

  private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
  private PrintStream err;

  @BeforeEach
  void clearActiveLine() throws UnsupportedEncodingException {
    System.clearProperty(AgentLauncher.ACTIVE_PROPERTY);
    Starting.calls = 0;
    err = new PrintStream(captured, true, "UTF-8");
  }

  @AfterEach
  void restoreActiveLine() {
    System.clearProperty(AgentLauncher.ACTIVE_PROPERTY);
  }

  @Test
  void readsTheFeatureVersionFromTheSpecificationVersion() {
    assertEquals(8, AgentLauncher.featureVersion("1.8"));
    assertEquals(7, AgentLauncher.featureVersion("1.7"));
    assertEquals(9, AgentLauncher.featureVersion("9"));
    assertEquals(11, AgentLauncher.featureVersion("11"));
    assertEquals(17, AgentLauncher.featureVersion("17"));
    assertEquals(21, AgentLauncher.featureVersion("21"));
    assertEquals(25, AgentLauncher.featureVersion("25"));
    assertEquals(26, AgentLauncher.featureVersion(" 26 "));
    assertEquals(-1, AgentLauncher.featureVersion(null));
    assertEquals(-1, AgentLauncher.featureVersion(""));
    assertEquals(-1, AgentLauncher.featureVersion("one"));
    assertEquals(-1, AgentLauncher.featureVersion("1."));
    // An absurdly long number must not overflow into an exception.
    assertEquals(123456789, AgentLauncher.featureVersion("1234567890123"));
  }

  @Test
  void choosesTheNewestAvailableLineThatFits() {
    assertEquals("java8", line(AgentLauncher.choose(8, ALL)));
    assertEquals("java11", line(AgentLauncher.choose(11, ALL)));
    assertEquals("java11", line(AgentLauncher.choose(16, ALL)));
    assertEquals("java17", line(AgentLauncher.choose(17, ALL)));
    assertEquals("java17", line(AgentLauncher.choose(20, ALL)));
    assertEquals(PRIMARY, line(AgentLauncher.choose(21, ALL)));
    assertEquals(PRIMARY, line(AgentLauncher.choose(25, ALL)));
    assertEquals(PRIMARY, line(AgentLauncher.choose(30, ALL)));
  }

  @Test
  void fitsNoLineOnJavaVersionsNoLineSupports() {
    assertEquals(-1, AgentLauncher.choose(7, ALL));
    assertEquals(-1, AgentLauncher.choose(9, ALL));
    assertEquals(-1, AgentLauncher.choose(10, ALL));
    assertEquals(-1, AgentLauncher.choose(-1, ALL));
  }

  @Test
  void usesOnlyTheLinesTheJarHolds() {
    boolean[] java8Only = {false, false, false, true};
    boolean[] java17Only = {false, true, false, false};
    boolean[] primaryOnly = {true, false, false, false};
    assertEquals("java8", line(AgentLauncher.choose(8, java8Only)));
    assertEquals(-1, AgentLauncher.choose(11, java8Only));
    assertEquals(-1, AgentLauncher.choose(25, java8Only));
    assertEquals(-1, AgentLauncher.choose(11, java17Only));
    assertEquals("java17", line(AgentLauncher.choose(25, java17Only)));
    assertEquals(-1, AgentLauncher.choose(17, primaryOnly));
    assertEquals(-1, AgentLauncher.choose(8, new boolean[0]));
  }

  @Test
  void startsTheChosenLineAndRecordsIt() {
    String started = launch(Starting.class.getName());
    assertEquals(PRIMARY, started);
    assertEquals(1, Starting.calls);
    assertEquals(PRIMARY, System.getProperty(AgentLauncher.ACTIVE_PROPERTY));
    assertEquals("", output());
  }

  @Test
  void aSecondLaunchSaysAnAgentIsActiveAndStartsNothing() {
    launch(Starting.class.getName());
    assertNull(launch(Starting.class.getName()));
    assertEquals(1, Starting.calls);
    assertEquals("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"already-active\",\"java_version\":\""
        + AgentLauncher.json(System.getProperty("java.version")) + "\",\"active_line\":\"primary\"}", output());
  }

  @Test
  void aLineThatThrowsIsReportedAndDoesNotEscape() {
    assertNull(launch(Throwing.class.getName()));
    String line = output();
    assertTrue(line.startsWith("{\"event\":\"ohmyrasp-agent-start-failed\",\"line\":\"primary\","), line);
    assertTrue(line.endsWith(",\"exception\":\"java.lang.NoClassDefFoundError\","
        + "\"message\":\"java/sql/DriverManager \\\"quoted\\\"\\n\\u0001\"}"), line);
  }

  @Test
  void anEntryWithoutTheMethodIsReportedAsAStartFailure() {
    assertNull(launch(NoEntryMethod.class.getName()));
    assertTrue(output().contains("\"exception\":\"java.lang.NoSuchMethodException\""), output());
  }

  @Test
  void aJarWithNoFittingLineIsSkipped() {
    assertNull(AgentLauncher.launch("premain", "", null, getClass().getClassLoader(),
        new String[] {MISSING, MISSING, MISSING, Starting.class.getName()}, err));
    assertEquals(0, Starting.calls);
    assertNull(System.getProperty(AgentLauncher.ACTIVE_PROPERTY));
    assertEquals("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\",\"java_version\":\""
        + AgentLauncher.json(System.getProperty("java.version")) + "\",\"lines\":\"java8\"}", output());
  }

  @Test
  void escapesJson() {
    assertEquals("a\\\\b\\\"c\\td\\u001f", AgentLauncher.json("a\\b\"c\td\u001f"));
  }

  /** Launches with {@code entry} as the primary line; the build JVM runs Java 21 or later. */
  private String launch(String entry) {
    return AgentLauncher.launch("premain", "", null, getClass().getClassLoader(),
        new String[] {entry, MISSING, MISSING, MISSING}, err);
  }

  private String output() {
    try {
      return captured.toString("UTF-8").trim();
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError(e);
    }
  }

  private static String line(int index) {
    return index < 0 ? "none" : AgentLauncher.LINES[index];
  }

  public static final class Starting {
    static int calls;

    public static void premain(String agentArgs, Instrumentation instrumentation) {
      calls++;
    }
  }

  public static final class Throwing {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
      throw new NoClassDefFoundError("java/sql/DriverManager \"quoted\"\n\u0001");
    }
  }

  public static final class NoEntryMethod {}
}
