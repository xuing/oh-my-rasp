package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
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

  /**
   * The daemon refuses to write a control document larger than {@code control/limits.properties}
   * says, because the agent ignores one: this side's constant is that value, and the agent reads
   * a document of exactly that size and not one byte more.
   */
  @Test
  void theControlSizeLimitIsTheContractValue() throws Exception {
    Properties limits = new Properties();
    limits.load(new StringReader(Java8ContractFiles.read("control/limits.properties")));
    int limit = Integer.parseInt(limits.getProperty("max_control_bytes"));
    assertEquals(limit, RaspRuntime.MAX_CONTROL_BYTES,
        "RaspRuntime.MAX_CONTROL_BYTES against control/limits.properties max_control_bytes");

    RaspRuntime.ControlState atLimit = new RaspRuntime.ControlState(null);
    atLimit.poll(placePadded(limit));
    assertEquals(RaspRuntime.Mode.BLOCK, atLimit.mode(), "a document of exactly the limit is read");

    RaspRuntime.ControlState overLimit = new RaspRuntime.ControlState(null);
    overLimit.poll(placePadded(limit + 1));
    assertNull(overLimit.mode(), "a document one byte over the limit is ignored");
  }

  /** {@code {"mode":"block"}} followed by spaces, {@code bytes} long in all. */
  private Path placePadded(int bytes) throws IOException {
    String json = "{\"mode\":\"block\"}";
    StringBuilder text = new StringBuilder(json);
    while (text.length() < bytes) {
      text.append(' ');
    }
    Path file = dir.resolve("padded-" + (placed++) + ".json");
    Files.write(file, text.toString().getBytes(StandardCharsets.UTF_8));
    return file;
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
