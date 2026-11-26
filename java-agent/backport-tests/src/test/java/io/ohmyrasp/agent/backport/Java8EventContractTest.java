package io.ohmyrasp.agent.backport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.java8.Java8RaspBlockException;
import io.ohmyrasp.agent.java8.Java8RaspHooks;
import io.ohmyrasp.agent.java8.Java8RaspLine;
import io.ohmyrasp.agent.java8.OhMyRaspJava8Agent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The event lines of the backport agents, built by the real hooks and written by the real
 * {@code RaspRuntime}, against {@code contracts/agent-daemon/events/backport/}. The daemon parses
 * the same files ({@code model.rs}). One test, run on all three backport lines: a line that wrote
 * anything but the shared golden line, apart from its own token, fails here.
 */
final class Java8EventContractTest {
  @TempDir Path dir;

  /**
   * The hooks log a monitored command once per thread until another is logged, and JUnit runs every
   * test class on one thread, so another class may have logged a scenario's command last. A
   * different command, written nowhere, makes each scenario's event its own.
   */
  @BeforeEach
  void forgetTheLastLoggedCommand() {
    System.setProperty("ohmyrasp.java8.log", "none");
    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /proc/self/environ"));
    System.clearProperty("ohmyrasp.java8.log");
  }

  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
  }

  @Test
  void aBlockedDetectionInsideAnHttpRequest() throws Exception {
    Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
    try {
      Java8RaspHooks.beforeHttpRequest(new ContractRequest("script", "ok; printf"));
      assertThrows(Java8RaspBlockException.class, () -> Java8RaspHooks.beforeProcessBuilderStart(
          new ProcessBuilder("/bin/sh", "-c", "printf ok; printf done")));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    Java8ContractFiles.assertGolden("events/backport/detection-block-request.json", only(log, true));
  }

  @Test
  void aMonitoredDetectionOutsideARequest() throws Exception {
    Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/shadow"));

    Java8ContractFiles.assertGolden("events/backport/detection-monitor-no-request.json", only(log, true));
  }

  @Test
  void theAgentStartLine() throws Exception {
    Path log = dir.resolve("events.jsonl");
    System.setProperty("ohmyrasp.java8.log", log.toString());

    // No Instrumentation, as in the other start-up tests: the line then says "missing".
    OhMyRaspJava8Agent.premain("", null);

    // The start lines of the three lines list their hooks in different orders, so each has its own file.
    Java8ContractFiles.assertGolden("events/backport/agent-start-" + Java8ContractFiles.lineToken() + ".json",
        only(log, false));
  }

  /**
   * The telemetry line is written only when the agent is not in synchronous mode, which the test
   * JVM is: a child JVM runs the production path with the writer thread, as an application would.
   */
  @Test
  void aSampledRequestLatencyIsATelemetryLine() throws Exception {
    Path log = dir.resolve("events.jsonl");
    List<String> command = new ArrayList<String>();
    command.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
    command.add("-cp");
    command.add(codeLocation(RaspRuntime.class) + File.pathSeparator + codeLocation(Java8RaspLine.class)
        + File.pathSeparator + codeLocation(Java8EventContractTest.class));
    command.add("-Dohmyrasp.java8.log=" + log);
    command.add("-Dohmyrasp.latency_sample=1");
    command.add("-Dohmyrasp.log.sync=false");
    command.add("-Dohmyrasp.control=none");
    command.add(TelemetryChild.class.getName());
    Process child = new ProcessBuilder(command).redirectErrorStream(true)
        .redirectOutput(dir.resolve("child.out").toFile()).start();
    assertTrue(child.waitFor(60, TimeUnit.SECONDS), "the child JVM finished");
    String output = new String(Files.readAllBytes(dir.resolve("child.out")), StandardCharsets.UTF_8);
    assertEquals(0, child.exitValue(), output);

    Java8ContractFiles.assertGolden("events/backport/telemetry.json", only(log, true));
  }

  /**
   * Runs in the child JVM of the telemetry test: starts the line as its entry class does, then one sampled
   * request latency.
   */
  public static final class TelemetryChild {
    public static void main(String[] args) {
      Java8RaspLine.start();
      RaspRuntime.sampleLatency(321);
    }
  }

  private static String codeLocation(Class<?> type) throws Exception {
    return new File(type.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
  }

  /** The one line the agent wrote, normalised; see {@link Java8ContractFiles#normalizeEvent}. */
  private static String only(Path log, boolean sharedAcrossLines) throws Exception {
    return Java8ContractFiles.normalizeEvent(Java8ContractFiles.onlyLine(log), sharedAcrossLines);
  }

  /** A servlet request, read by the agent through reflection like a container's. */
  public static final class ContractRequest {
    private final Map<String, String[]> parameters = new HashMap<String, String[]>();

    ContractRequest(String name, String value) {
      parameters.put(name, new String[] {value});
    }

    public String getMethod() {
      return "POST";
    }

    public String getRequestURI() {
      return "/app/format";
    }

    public String getQueryString() {
      return "";
    }

    public Map<String, String[]> getParameterMap() {
      return parameters;
    }

    public String getHeader(String name) {
      return null;
    }

    public Object[] getCookies() {
      return new Object[0];
    }
  }
}
