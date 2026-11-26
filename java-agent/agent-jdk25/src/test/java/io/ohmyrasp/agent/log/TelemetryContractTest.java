package io.ohmyrasp.agent.log;


import io.ohmyrasp.agent.contract.ContractFiles;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The latency telemetry line of the primary agent, written by the real {@link JsonEventLogger},
 * against {@code contracts/agent-daemon/events/primary/telemetry.json}. The daemon feeds only its
 * latency panel from it.
 */
final class TelemetryContractTest {
  @Test
  void aSampledHookLatencyIsATelemetryLine(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    // Asynchronous with a sample rate of 1: the production telemetry path. Shutdown writes the queue.
    JsonEventLogger logger = JsonEventLogger.newForTesting(null, log.toString(), 1, false, console, console);

    logger.sampleHookLatency("http_request", 321);
    logger.shutdown(5000);

    ContractFiles.assertGolden("events/primary/telemetry.json", ContractFiles.normalizeEvent(ContractFiles.onlyLine(log)));
  }
}
