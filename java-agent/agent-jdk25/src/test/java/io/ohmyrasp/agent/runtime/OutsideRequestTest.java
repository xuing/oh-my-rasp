package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hook.OhMyRaspBlockException;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The control setting {@code outside_request}: whether a finding made on a thread that serves no HTTP request
 * blocks. Block by default, as on the backport lines; {@code log} records it and lets the operation run.
 */
final class OutsideRequestTest {
  private static final String LDAP = "ldap://127.0.0.1:1/Exploit";

  @AfterEach
  void restoreTheSharedRuntime() {
    // A control file that does not exist returns every setting to its start-up value.
    AgentRuntime.get().reloadIfChanged(Path.of("/nonexistent/ohmyrasp-outside-request-test.json"));
  }

  @Test
  void blockModeBlocksAFindingOutsideARequestByDefault() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));
    assertFalse(OhMyRaspHooks.currentRequest().active());

    assertThrows(OhMyRaspBlockException.class, () -> OhMyRaspHooks.beforeJndiLookup(LDAP));
  }

  @Test
  void logOnlyOutsideARequestRecordsTheFindingAndLetsTheOperationRun() {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeJndiLookup(LDAP));
  }

  /** ssrf_protocol and ssrf_obfuscate are too broad to block without a request that supplied the URL. */
  @Test
  void aRequestOnlyRuleLogsOutsideARequestWhateverTheSetting() throws Exception {
    assertTrue(AgentRuntime.get().apply("{\"mode\":\"block\"}"));

    assertDoesNotThrow(() -> OhMyRaspHooks.beforeUrlOpen(URI.create("ftp://127.0.0.1:1/report.csv").toURL()));
    assertThrows(OhMyRaspBlockException.class,
        () -> OhMyRaspHooks.beforeUrlOpen(URI.create("http://169.254.169.254/latest/meta-data/").toURL()));
  }

  @Test
  void anAbsentOrNullMemberMeansTheStartUpValueAndAValueNobodyAcceptsChangesNothing() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    assertTrue(runtime.state().outsideRequestBlocks(), "block before any setting");

    for (String unknown : new String[] {"\"sometimes\"", "\"monitor\"", "7", "true", "{}"}) {
      assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":\" LOG \"}"));
      assertFalse(runtime.state().outsideRequestBlocks(), "any case, padded");
      assertTrue(runtime.apply("{\"mode\":\"monitor\",\"outside_request\":" + unknown + "}"));
      assertFalse(runtime.state().outsideRequestBlocks(), unknown + " keeps log");
      assertEquals(DetectionMode.MONITOR, runtime.mode(), unknown + ": the rest of the document applies");
    }
    assertTrue(runtime.apply("{\"mode\":\"block\"}"));
    assertTrue(runtime.state().outsideRequestBlocks(), "absent: the start-up value");
    assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":\"log\"}"));
    assertTrue(runtime.apply("{\"mode\":\"block\",\"outside_request\":null}"));
    assertTrue(runtime.state().outsideRequestBlocks(), "null: the start-up value");
  }

  @Test
  void theStartUpValueComesFromTheAgentArgumentAndARemovedFileReturnsToIt(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block,outside_request=log");
    assertFalse(runtime.state().outsideRequestBlocks(), "the agent argument");

    Files.writeString(file, "{\"mode\":\"block\",\"outside_request\":\"block\"}");
    runtime.reloadIfChanged();
    assertTrue(runtime.state().outsideRequestBlocks(), "the control file overrides it");
    Files.writeString(file, "{\"mode\":\"block\"}");
    runtime.reloadIfChanged();
    assertFalse(runtime.state().outsideRequestBlocks(), "a document without it: the start-up value");
    Files.writeString(file, "{\"mode\":\"block\",\"outside_request\":\"block\"}");
    runtime.reloadIfChanged();
    Files.delete(file);
    runtime.reloadIfChanged();
    assertFalse(runtime.state().outsideRequestBlocks(), "a removed file: the start-up value");
  }

  @Test
  void anUnusableAgentArgumentLeavesTheNextSourceInCharge() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=none,mode=block,outside_request=sometimes");
    assertTrue(runtime.state().outsideRequestBlocks());
  }

  /** Under lock_config only the baked value counts, as for mode. */
  @Test
  void aLockedProfileTakesOnlyTheBakedValue() {
    Properties baked = new Properties();
    baked.setProperty("standalone", "true");
    baked.setProperty("lock_config", "true");
    baked.setProperty("mode", "block");
    baked.setProperty("outside_request", "log");
    AgentRuntime locked = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(baked));
    locked.start("outside_request=block", ShirudoDefaults.fromProperties(baked));
    assertFalse(locked.state().outsideRequestBlocks());

    baked.remove("outside_request");
    AgentRuntime lockedDefault = AgentRuntime.newForTesting(ShirudoDefaults.fromProperties(baked));
    lockedDefault.start("outside_request=log", ShirudoDefaults.fromProperties(baked));
    assertTrue(lockedDefault.state().outsideRequestBlocks(), "nothing baked: the default, not the argument");
  }
}
