package io.ohmyrasp.agent.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.concurrent.CountDownLatch;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentLauncherTest {
  private static final String MISSING = "io.ohmyrasp.agent.launch.NoSuchEntry";
  private static final boolean[] ALL = {true, true, true, true};

  private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
  private PrintStream err;

  @TempDir File temp;

  @BeforeEach
  void prepare() throws UnsupportedEncodingException {
    clearState();
    Starting.calls = 0;
    Slow.calls = 0;
    err = new PrintStream(captured, true, "UTF-8");
  }

  @AfterEach
  void clearState() {
    setState(null);
    System.clearProperty(AgentLauncher.STATE_PROPERTY);
    System.clearProperty(AgentLauncher.LINE_PROPERTY);
  }

  /** The launcher's own state; tests reset it, nothing in the agent writes it from outside. */
  private static void setState(String value) {
    try {
      Field field = AgentLauncher.class.getDeclaredField("state");
      field.setAccessible(true);
      field.set(null, value);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
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
    assertEquals("primary", line(AgentLauncher.choose(21, ALL)));
    assertEquals("primary", line(AgentLauncher.choose(25, ALL)));
    assertEquals("primary", line(AgentLauncher.choose(30, ALL)));
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
  void startsTheChosenLineAndRecordsIt() throws IOException {
    assertEquals("primary", launch(Starting.class.getName()));
    assertEquals(1, Starting.calls);
    assertEquals("installed:primary", System.getProperty(AgentLauncher.STATE_PROPERTY));
    assertEquals("primary", System.getProperty(AgentLauncher.LINE_PROPERTY));
    assertEquals("", output());
  }

  @Test
  void aSecondLaunchSaysAnAgentIsActiveAndStartsNothing() throws IOException {
    launch(Starting.class.getName());
    assertNull(launch(Starting.class.getName()));
    assertEquals(1, Starting.calls);
    assertEquals("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"already-active\",\"java_version\":\""
        + javaVersion() + "\",\"state\":\"installed:primary\"}", output());
  }

  @Test
  void aLaunchDuringAnotherStartStartsNothing() throws IOException {
    setState("starting");
    assertNull(launch(Starting.class.getName()));
    assertEquals(0, Starting.calls);
    assertTrue(output().contains("\"reason\":\"already-active\",\"java_version\""), output());
  }

  @Test
  void anotherDefinitionsStateStopsThisLaunch() throws Exception {
    // A second definition of AgentLauncher, as the bootstrap loader makes once a line appended its JAR.
    URL classes = AgentLauncher.class.getProtectionDomain().getCodeSource().getLocation();
    URLClassLoader loader = new URLClassLoader(new URL[] {classes}, null);
    try {
      Class<?> other = loader.loadClass(AgentLauncher.class.getName());
      Field field = other.getDeclaredField("state");
      field.setAccessible(true);
      field.set(null, "installed:java8");
      assertNull(AgentLauncher.launch("agentmain", "", loadedClasses(AgentLauncher.class, other), getClass(),
          getClass().getClassLoader(), new String[] {Starting.class.getName(), MISSING, MISSING, MISSING}, err));
      assertEquals(0, Starting.calls);
      assertTrue(output().endsWith("\"state\":\"installed:java8\"}"), output());
      // And the other way round: this definition's state is what the other one reads.
      field.set(null, null);
      captured.reset();
      assertEquals("primary", launch(Starting.class.getName()));
      Method recorded = other.getDeclaredMethod("recorded", Instrumentation.class);
      recorded.setAccessible(true);
      assertEquals("installed:primary", recorded.invoke(null, loadedClasses(other, AgentLauncher.class)));
    } finally {
      loader.close();
    }
  }

  @Test
  void racingLaunchesStartOneLine() throws Exception {
    final CountDownLatch ready = new CountDownLatch(2);
    final String[] results = new String[2];
    Thread[] threads = new Thread[2];
    for (int i = 0; i < 2; i++) {
      final int index = i;
      threads[i] = new Thread(new Runnable() {
        @Override
        public void run() {
          ready.countDown();
          try {
            ready.await();
            results[index] = launch(Slow.class.getName());
          } catch (Exception e) {
            results[index] = e.toString();
          }
        }
      });
      threads[i].start();
    }
    for (Thread thread : threads) {
      thread.join(10000);
    }
    assertEquals(1, Slow.calls);
    assertTrue("primary".equals(results[0]) != "primary".equals(results[1]), results[0] + " " + results[1]);
    assertTrue(output().contains("\"reason\":\"already-active\""), output());
  }

  /** An Instrumentation whose getAllLoadedClasses returns {@code classes}; nothing else is called. */
  private static Instrumentation loadedClasses(final Class<?>... classes) {
    return (Instrumentation) Proxy.newProxyInstance(Instrumentation.class.getClassLoader(),
        new Class<?>[] {Instrumentation.class}, new InvocationHandler() {
          @Override
          public Object invoke(Object proxy, Method method, Object[] args) {
            if (method.getName().equals("getAllLoadedClasses")) {
              return classes;
            }
            throw new UnsupportedOperationException(method.getName());
          }
        });
  }

  @Test
  void statePropertiesSetFromOutsideDoNotStopTheStart() throws IOException {
    // As if the command line carried -Dohmyrasp.agent.state=installed:primary -Dohmyrasp.agent.line=x.
    System.setProperty(AgentLauncher.STATE_PROPERTY, "installed:primary");
    System.setProperty(AgentLauncher.LINE_PROPERTY, "x");
    assertEquals("primary", launch(Starting.class.getName()));
    assertEquals(1, Starting.calls);
    assertEquals("", output());
    assertEquals("installed:primary", System.getProperty(AgentLauncher.STATE_PROPERTY));
    assertEquals("primary", System.getProperty(AgentLauncher.LINE_PROPERTY));
  }

  @Test
  void aLineThatThrowsIsReportedAndNoLaterLaunchStartsALine() throws IOException {
    assertNull(launch(Throwing.class.getName()));
    String failed = output();
    assertTrue(failed.startsWith("{\"event\":\"ohmyrasp-agent-start-failed\",\"line\":\"primary\","
        + "\"protection\":\"inactive or incomplete\","), failed);
    assertTrue(failed.endsWith(",\"exception\":\"java.lang.NoClassDefFoundError\","
        + "\"message\":\"java/sql/DriverManager \\\"quoted\\\"\\n\\u0001\"}"), failed);
    assertEquals("failed:primary", System.getProperty(AgentLauncher.STATE_PROPERTY));
    assertNull(System.getProperty(AgentLauncher.LINE_PROPERTY));

    captured.reset();
    // A later JAR or attach, even with a line that would start, must not install over a partial start.
    assertNull(launch(Starting.class.getName()));
    assertEquals(0, Starting.calls);
    assertEquals("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"earlier-start-failed\",\"java_version\":\""
        + javaVersion() + "\",\"state\":\"failed:primary\"}", output());
  }

  @Test
  void anEntryWithoutTheMethodIsReportedAsAStartFailure() throws IOException {
    assertNull(launch(NoEntryMethod.class.getName()));
    assertTrue(output().contains("\"exception\":\"java.lang.NoSuchMethodException\""), output());
    assertEquals("failed:primary", System.getProperty(AgentLauncher.STATE_PROPERTY));
  }

  @Test
  void aJarWithNoFittingLineIsSkippedAndLeavesNoState() throws IOException {
    assertNull(AgentLauncher.launch("premain", "", null, getClass(), getClass().getClassLoader(),
        new String[] {MISSING, MISSING, MISSING, Starting.class.getName()}, err));
    assertEquals(0, Starting.calls);
    assertNull(System.getProperty(AgentLauncher.STATE_PROPERTY));
    assertTrue(output().startsWith("{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\","
        + "\"java_version\":\"" + javaVersion() + "\",\"lines\":\"java8\",\"jar\":\""), output());
  }

  @Test
  void looksForLinesInTheEntrysOwnJarFile() throws IOException {
    File jar = new File(temp, "agent.jar");
    ZipOutputStream out = new ZipOutputStream(new FileOutputStream(jar));
    try {
      out.putNextEntry(new ZipEntry("io/ohmyrasp/agent/java17/OhMyRaspJava17Agent.class"));
      out.closeEntry();
    } finally {
      out.close();
    }
    assertTrue(AgentLauncher.holds(jar, "io.ohmyrasp.agent.java17.OhMyRaspJava17Agent"));
    assertFalse(AgentLauncher.holds(jar, "io.ohmyrasp.agent.OhMyRaspAgent"));
  }

  @Test
  void findsTheEntrysArtifact() throws IOException {
    File artifact = AgentLauncher.artifactOf(getClass());
    assertTrue(AgentLauncher.holds(artifact, getClass().getName()), String.valueOf(artifact));
    String path = "io/ohmyrasp/agent/launch/Java8Entry.class";
    assertEquals(new URL("file:/opt/agent%20dir/ohmyrasp-agent-java8.jar"), AgentLauncher.containerOf(
        new URL("jar:file:/opt/agent%20dir/ohmyrasp-agent-java8.jar!/" + path), path));
    assertEquals(new URL("file:/build/classes/"),
        AgentLauncher.containerOf(new URL("file:/build/classes/" + path), path));
    assertNull(AgentLauncher.containerOf(null, path));
  }

  @Test
  void escapesJson() {
    assertEquals("a\\\\b\\\"c\\td\\u001f", AgentLauncher.json("a\\b\"c\td\u001f"));
  }

  /**
   * Launches with this test class as the entry, so the artifact is the test class directory, and
   * {@code lineEntry} as the primary line; the build JVM runs Java 21 or later.
   */
  private String launch(String lineEntry) throws IOException {
    return AgentLauncher.launch("premain", "", null, getClass(), getClass().getClassLoader(),
        new String[] {lineEntry, MISSING, MISSING, MISSING}, err);
  }

  private String output() {
    try {
      return captured.toString("UTF-8").trim();
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError(e);
    }
  }

  private static String javaVersion() {
    return AgentLauncher.json(System.getProperty("java.version"));
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

  public static final class Slow {
    static volatile int calls;

    public static void premain(String agentArgs, Instrumentation instrumentation) throws InterruptedException {
      calls++;
      Thread.sleep(300);
    }
  }

  public static final class Throwing {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
      throw new NoClassDefFoundError("java/sql/DriverManager \"quoted\"\n\u0001");
    }
  }

  public static final class NoEntryMethod {}
}
