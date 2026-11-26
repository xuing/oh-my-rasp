package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.contract.ContractFiles;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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

  private static void assertSame(String name, AgentRuntime.ControlState before, AgentRuntime.ControlState after) {
    assertTrue(before == after, name + " was applied: a rejected document published a new state");
  }

  private void assertState(String document, Properties expected, AgentRuntime runtime) {
    AgentRuntime.ControlState state = runtime.state();
    String mode = expected.getProperty(document + ".mode");
    assertEquals(mode, state.mode() == null ? null : state.mode().name().toLowerCase(), document + " mode");
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
