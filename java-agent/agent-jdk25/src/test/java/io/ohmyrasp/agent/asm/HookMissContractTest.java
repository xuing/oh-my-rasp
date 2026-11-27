package io.ohmyrasp.agent.asm;

import static io.ohmyrasp.agent.asm.HookMissReportTest.CHANGED;
import static io.ohmyrasp.agent.asm.HookMissReportTest.HANDLER;
import static io.ohmyrasp.agent.asm.HookMissReportTest.TABLE;
import static io.ohmyrasp.agent.asm.HookMissReportTest.classWith;
import static io.ohmyrasp.agent.asm.HookMissReportTest.domain;
import static io.ohmyrasp.agent.asm.HookMissReportTest.jar;
import static io.ohmyrasp.agent.asm.HookMissReportTest.transform;

import io.ohmyrasp.agent.contract.ContractFiles;
import io.ohmyrasp.agent.hookmiss.HookExpectations;
import io.ohmyrasp.agent.hookmiss.HookMissSink;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.log.HookMissLines;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The hook-miss lines of the primary agent, made by the real transformer and module and written by the real
 * {@link JsonEventLogger}, against {@code contracts/agent-daemon/events/primary/}. The daemon parses the same
 * files ({@code model.rs}).
 */
final class HookMissContractTest {
  @AfterEach
  void stop() {
    HookMisses.stop();
  }

  @Test
  void aHookThatDidNotApply(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    HookMisses.start(HookExpectations.parse(TABLE), new HookMissLines(logger(log)), true);
    Path jar = jar(dir.resolve("mybatis-9.9.9.jar"), "9.9.9");

    transform(HANDLER, classWith(HANDLER, CHANGED), domain(jar.toUri().toURL()));

    ContractFiles.assertGolden("events/primary/diagnostic-hook-miss.json", ContractFiles.normalizeEvent(ContractFiles.onlyLine(log)));
  }

  @Test
  void theLineAfterTheLimit(@TempDir Path dir) throws Exception {
    Path log = dir.resolve("events.jsonl");
    HookMissLines real = new HookMissLines(logger(log));
    StringBuilder table = new StringBuilder();
    for (int i = 0; i <= HookMisses.LIMIT; i++) {
      table.append("SqlHookModule org/h2/jdbc/Missing").append(i).append(" report execute(Ljava/lang/String;)Z\n");
    }
    // Only the last line reaches the log: the lines before it are the other golden file's kind.
    HookMisses.start(HookExpectations.parse(table.toString()), new HookMissSink() {
      @Override public void write(String diagnostic, String fields) {
        if (diagnostic.equals("hook_miss_suppressed")) {
          real.write(diagnostic, fields);
        }
      }

      @Override public boolean enterOwnIo() {
        return real.enterOwnIo();
      }

      @Override public void exitOwnIo(boolean entered) {
        real.exitOwnIo(entered);
      }
    }, true);

    for (int i = 0; i <= HookMisses.LIMIT; i++) {
      transform("org/h2/jdbc/Missing" + i, classWith("org/h2/jdbc/Missing" + i, "close()V"), null);
    }

    ContractFiles.assertGolden("events/primary/diagnostic-hook-miss-suppressed.json",
        ContractFiles.normalizeEvent(ContractFiles.onlyLine(log)));
  }

  private static JsonEventLogger logger(Path log) {
    PrintStream console = new PrintStream(new ByteArrayOutputStream());
    // Synchronous, so the line is on disk when the transform returns; no latency telemetry.
    return JsonEventLogger.newForTesting(null, log.toString(), 0, true, console, console);
  }
}
