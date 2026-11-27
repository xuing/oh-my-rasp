package io.ohmyrasp.agent.hook;

import static org.junit.jupiter.api.Assertions.assertThrows;

import io.ohmyrasp.agent.contract.ContractFiles;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The detection lines of the primary agent, built by the real hooks and written by the real
 * {@link JsonEventLogger}, against {@code contracts/agent-daemon/events/primary/}. The daemon
 * parses the same files ({@code model.rs}).
 */
final class EventContractTest {
  private static final String SCRIPT = "/srv/app/webapps/ROOT/shell.jsp";

  @AfterEach
  void reset() {
    OhMyRaspHooks.reportTo(null);
    OhMyRaspHooks.exitHttpRequest();
    System.clearProperty("ohmyrasp.block");
  }

  @Test
  void aBlockedDetectionInsideAnHttpRequestCarriesTheRequestWithSecretsRedacted(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));
    System.setProperty("ohmyrasp.block", "true");

    OhMyRaspHooks.enterHttpRequest(new ContractRequest(), new Object());
    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeFileWrite(SCRIPT));

    ContractFiles.assertGolden("events/primary/detection-block-request.json", only(log));
  }

  @Test
  void aMonitoredDetectionOutsideARequestHasAnEmptyRequest(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));

    OhMyRaspHooks.beforeUrlOpen(new URL("http://169.254.169.254/latest/meta-data/"));

    ContractFiles.assertGolden("events/primary/detection-monitor-no-request.json", only(log));
  }

  /**
   * The strings the daemon reads at the top level of a line to tell a diagnostic from a detection can appear in a
   * detection's data (here the URL the application opened). The writer escapes them, so they are inside a string,
   * and the line stays a detection: {@code daemon/src/contract_tests.rs} reads the same file.
   */
  @Test
  void aDetectionWhoseDataHoldsTheStringsThatMarkADiagnosticIsStillADetection(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    OhMyRaspHooks.reportTo(logger(log));

    OhMyRaspHooks.beforeUrlOpen(new URL(
        "http://169.254.169.254/latest/meta-data/\"kind\":\"diagnostic\",\"event\":\"ohmyrasp-hook-miss\",\"diagnostic\":\"hook_miss\""));

    ContractFiles.assertGolden("events/primary/detection-reserved-strings.json", only(log));
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    // Synchronous, so the line is on disk when the hook returns; no latency telemetry.
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }

  /** The one line the hooks wrote, normalised. */
  private static String only(Path log) throws Exception {
    return ContractFiles.normalizeEvent(ContractFiles.onlyLine(log));
  }

  /** A servlet request, read by the agent through reflection like a container's. */
  public static final class ContractRequest {
    private final Map<String, String> headers = new LinkedHashMap<>();

    ContractRequest() {
      headers.put("user-agent", "contract-test/1.0");
      headers.put("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.contract.signature");
      headers.put("cookie", "JSESSIONID=0123456789ABCDEF");
      // Not a form: the parameters beyond the query string are then not a body the container parsed, and the event
      // shows the request's parameters, redacted (a form body's would be withheld: see BodyEvidence).
      headers.put("content-type", "application/json");
    }

    public String getMethod() {
      return "POST";
    }

    public String getRequestURI() {
      return "/app/upload";
    }

    public String getQueryString() {
      return "folder=reports&password=hunter2";
    }

    public Map<String, List<String>> getParameterMap() {
      Map<String, List<String>> parameters = new LinkedHashMap<>();
      parameters.put("folder", List.of("reports"));
      parameters.put("password", List.of("hunter2"));
      parameters.put("label", List.of("a", "b \"quoted\""));
      return parameters;
    }

    public Enumeration<String> getHeaderNames() {
      return Collections.enumeration(headers.keySet());
    }

    public String getHeader(String name) {
      return headers.get(name);
    }
  }
}
