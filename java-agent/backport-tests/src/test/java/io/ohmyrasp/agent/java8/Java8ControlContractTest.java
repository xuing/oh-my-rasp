package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every control document the daemon writes ({@code contracts/agent-daemon/control/}, produced by
 * the daemon's {@code Controller}), read through the production {@code RaspRuntime} poller, and
 * the documents it must refuse. The backport lines read the mode and nothing else from the file:
 * the per-algorithm switches, the revision and the policy are primary-agent settings, so
 * {@code control/expected.properties} is checked here for the mode only.
 */
final class Java8ControlContractTest {
  @TempDir Path dir;
  private int placed;

  @Test
  void everyDocumentTheDaemonWritesSetsTheModeTheManifestSays() throws Exception {
    Properties expected = expected();
    List<String> documents = documents("control");
    List<String> inManifest = new ArrayList<String>();
    for (String key : expected.stringPropertyNames()) {
      if (key.endsWith(".mode")) {
        inManifest.add(key.substring(0, key.length() - ".mode".length()));
      }
    }
    assertEquals(new TreeSet<String>(inManifest), new TreeSet<String>(documents),
        "control/expected.properties and the control/*.json files list the same documents");
    for (String document : documents) {
      RaspRuntime.ControlState state = new RaspRuntime.ControlState(null);
      state.poll(place("control/" + document + ".json"));
      assertEquals(expected.getProperty(document + ".mode"), state.mode().name().toLowerCase(java.util.Locale.ROOT), document);
    }
  }

  /** A document that is not one well-formed JSON object changes nothing, whatever it says. */
  @Test
  void aRejectedDocumentLeavesTheModeUnchanged() throws Exception {
    List<String> rejected = documents("control/rejected");
    assertTrue(rejected.size() >= 4, "the rejected fixtures are there: " + rejected);
    for (String name : rejected) {
      RaspRuntime.ControlState state = new RaspRuntime.ControlState(RaspRuntime.Mode.BLOCK);
      state.poll(place("control/mode-monitor.json"));
      assertEquals(RaspRuntime.Mode.MONITOR, state.mode(), "the baseline document applies");

      state.poll(place("control/rejected/" + name + ".json"));

      assertEquals(RaspRuntime.Mode.MONITOR, state.mode(), name + " must not change the mode (it says off)");
    }
  }

  /** Copies the fixture to a fresh file, as the daemon's rename would leave it, and returns the path. */
  private Path place(String relative) throws IOException {
    Path file = dir.resolve("control-" + (placed++) + ".json");
    Files.copy(Java8ContractFiles.dir().resolve(relative), file);
    return file;
  }

  private static Properties expected() throws IOException {
    Properties properties = new Properties();
    properties.load(new StringReader(Java8ContractFiles.read("control/expected.properties")));
    return properties;
  }

  private static List<String> documents(String relative) {
    List<String> names = new ArrayList<String>();
    for (Path file : Java8ContractFiles.files(relative)) {
      String name = file.getFileName().toString();
      if (name.endsWith(".json")) {
        names.add(name.substring(0, name.length() - ".json".length()));
      }
    }
    return names;
  }
}
