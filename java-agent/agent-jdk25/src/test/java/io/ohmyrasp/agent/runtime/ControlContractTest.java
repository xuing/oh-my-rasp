package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.contract.ContractFiles;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every control document the daemon writes ({@code contracts/agent-daemon/control/}, produced by
 * the daemon's {@code Controller}), read through the production poller, and the documents it must
 * refuse. {@code control/expected.properties} says what each one means.
 */
final class ControlContractTest {
  @TempDir Path dir;

  @Test
  void everyDocumentTheDaemonWritesAppliesAsTheManifestSays() throws Exception {
    Properties expected = expected();
    List<String> documents = documents("control");
    assertEquals(new TreeSet<>(manifestDocuments(expected)), new TreeSet<>(documents),
        "control/expected.properties and the control/*.json files list the same documents");
    for (String document : documents) {
      AgentRuntime runtime = AgentRuntime.newForTesting();
      runtime.reloadIfChanged(place("control/" + document + ".json"));
      assertState(document, expected, runtime);
    }
  }

  /**
   * An operator edits the daemon's file by hand ({@code control/hand-edited/}): every spelling of
   * the mode that both agent engines accept, in any letter case. The agent must read each as
   * {@code control/hand-edited/expected.properties} says; the daemon reads the same documents.
   */
  @Test
  void everyHandEditedDocumentAppliesAsItsManifestSays() throws Exception {
    Properties expected = new Properties();
    expected.load(new StringReader(ContractFiles.read("control/hand-edited/expected.properties")));
    List<String> documents = documents("control/hand-edited");
    assertEquals(new TreeSet<>(manifestDocuments(expected)), new TreeSet<>(documents),
        "control/hand-edited/expected.properties and the hand-edited/*.json files list the same documents");
    assertTrue(documents.size() >= 10, "the spellings are there: " + documents);
    for (String document : documents) {
      AgentRuntime runtime = AgentRuntime.newForTesting();
      runtime.reloadIfChanged(place("control/hand-edited/" + document + ".json"));
      AgentRuntime.ControlState state = runtime.state();
      assertEquals(expected.getProperty(document + ".mode"), state.mode() == null ? null : state.mode().token(),
          document + " mode");
      assertEquals(Long.parseLong(expected.getProperty(document + ".revision")), state.revision(), document + " revision");
      for (String algorithm : list(expected, document + ".disabled")) {
        assertFalse(state.isAlgorithmEnabled(algorithm), document + ": " + algorithm + " is disabled");
      }
      for (String algorithm : list(expected, document + ".enabled")) {
        assertTrue(state.isAlgorithmEnabled(algorithm), document + ": " + algorithm + " is enabled");
      }
      String outside = expected.getProperty(document + ".outside_request");
      if ("unknown".equals(outside)) {
        // A value nobody accepts changes nothing: the start-up value, or what an earlier document set.
        assertTrue(state.outsideRequestBlocks(), document + " outside_request keeps the start-up value");
        AgentRuntime primed = AgentRuntime.newForTesting();
        primed.reloadIfChanged(place("control/outside-request-log.json"));
        primed.reloadIfChanged(place("control/hand-edited/" + document + ".json"));
        assertFalse(primed.state().outsideRequestBlocks(), document + " outside_request keeps log");
        assertEquals(DetectionMode.BLOCK, primed.state().mode(), document + " still applies its mode");
      } else {
        assertEquals(outside, outsideRequest(state), document + " outside_request");
      }
    }
  }

  /** The daemon withdraws a policy by rewriting the file without the key: the agent must drop it. */
  @Test
  void aPolicyTheDaemonWithdrawsStopsApplying() throws Exception {
    Properties expected = expected();
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.reloadIfChanged(place("control/policy-installed.json"));
    assertState("policy-installed", expected, runtime);
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());

    runtime.reloadIfChanged(place("control/policy-withdrawn.json"));
    assertState("policy-withdrawn", expected, runtime);
    assertEquals(AgentRuntime.PolicySource.NONE, runtime.state().policySource());
    assertFalse(runtime.policy().loaded());
  }

  /** A document that is not one well-formed JSON object changes nothing, whatever it says. */
  @Test
  void aRejectedDocumentLeavesTheStateUnchanged() throws Exception {
    Properties expected = expected();
    List<String> rejected = documents("control/rejected");
    assertTrue(rejected.size() >= 4, "the rejected fixtures are there: " + rejected);
    for (String name : rejected) {
      AgentRuntime runtime = AgentRuntime.newForTesting();
      runtime.reloadIfChanged(place("control/policy-installed.json"));
      AgentRuntime.ControlState before = runtime.state();

      runtime.reloadIfChanged(place("control/rejected/" + name + ".json"));

      assertSame(name, before, runtime.state());
      assertState("policy-installed", expected, runtime);
    }
  }

  /**
   * The daemon refuses to write a control document larger than {@code control/limits.properties}
   * says, because the agent ignores one: this side's constant is that value, and the agent reads
   * a document of exactly that size and not one byte more.
   */
  @Test
  void theControlSizeLimitIsTheContractValue() throws Exception {
    int limit = contractLimit();
    assertEquals(limit, AgentRuntime.MAX_CONTROL_BYTES,
        "AgentRuntime.MAX_CONTROL_BYTES against control/limits.properties max_control_bytes");

    AgentRuntime atLimit = AgentRuntime.newForTesting();
    atLimit.reloadIfChanged(placePadded(limit));
    assertEquals(DetectionMode.BLOCK, atLimit.mode(), "a document of exactly the limit is read");

    AgentRuntime overLimit = AgentRuntime.newForTesting();
    overLimit.reloadIfChanged(placePadded(limit + 1));
    assertNull(overLimit.mode(), "a document one byte over the limit is ignored");
  }

  /** {@code {"mode":"block"}} followed by spaces, {@code bytes} long in all. */
  private Path placePadded(int bytes) throws IOException {
    String json = "{\"mode\":\"block\"}";
    byte[] content = (json + " ".repeat(bytes - json.length())).getBytes(StandardCharsets.UTF_8);
    Path file = dir.resolve("padded-" + bytes + ".json");
    Files.write(file, content);
    return file;
  }

  private static int contractLimit() throws IOException {
    Properties limits = new Properties();
    limits.load(new StringReader(ContractFiles.read("control/limits.properties")));
    return Integer.parseInt(limits.getProperty("max_control_bytes"));
  }

  private static void assertSame(String name, AgentRuntime.ControlState before, AgentRuntime.ControlState after) {
    assertTrue(before == after, name + " was applied: a rejected document published a new state");
  }

  private static String outsideRequest(AgentRuntime.ControlState state) {
    return state.outsideRequestBlocks() ? "block" : "log";
  }

  private void assertState(String document, Properties expected, AgentRuntime runtime) {
    AgentRuntime.ControlState state = runtime.state();
    assertEquals(expected.getProperty(document + ".outside_request"), outsideRequest(state), document + " outside_request");
    String mode = expected.getProperty(document + ".mode");
    assertEquals(mode, state.mode() == null ? null : state.mode().name().toLowerCase(Locale.ROOT), document + " mode");
    assertEquals(Long.parseLong(expected.getProperty(document + ".revision")), state.revision(), document + " revision");
    for (String algorithm : list(expected, document + ".disabled")) {
      assertFalse(state.isAlgorithmEnabled(algorithm), document + ": " + algorithm + " is disabled");
    }
    for (String algorithm : list(expected, document + ".enabled")) {
      assertTrue(state.isAlgorithmEnabled(algorithm), document + ": " + algorithm + " is enabled");
    }
    String policy = expected.getProperty(document + ".policy");
    if (policy.equals("none")) {
      assertEquals(AgentRuntime.PolicySource.NONE, state.policySource(), document + " policy source");
      assertFalse(state.policy().loaded(), document + " policy");
    } else {
      assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, state.policySource(), document + " policy source");
      assertTrue(state.policy().loaded(), document + " policy");
      assertEquals(Integer.parseInt(expected.getProperty(document + ".policy.version")), state.policy().version(),
          document + " policy version");
    }
  }

  /** Copies the fixture to a fresh file, as the daemon's rename would leave it, and returns the path. */
  private Path place(String relative) throws IOException {
    Path file = dir.resolve("control-" + System.nanoTime() + ".json");
    Files.copy(ContractFiles.dir().resolve(relative), file);
    return file;
  }

  private static Properties expected() throws IOException {
    Properties properties = new Properties();
    properties.load(new StringReader(ContractFiles.read("control/expected.properties")));
    return properties;
  }

  private static List<String> manifestDocuments(Properties expected) {
    List<String> names = new ArrayList<>();
    for (String key : expected.stringPropertyNames()) {
      if (key.endsWith(".mode")) {
        names.add(key.substring(0, key.length() - ".mode".length()));
      }
    }
    return names;
  }

  private static List<String> documents(String relative) {
    List<String> names = new ArrayList<>();
    for (Path file : ContractFiles.files(relative)) {
      String name = file.getFileName().toString();
      if (name.endsWith(".json")) {
        names.add(name.substring(0, name.length() - ".json".length()));
      }
    }
    return names;
  }

  private static List<String> list(Properties expected, String key) {
    String value = expected.getProperty(key, "").trim();
    return value.isEmpty() ? List.of() : Arrays.asList(value.split("\\s*,\\s*"));
  }
}
