package io.ohmyrasp.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.policy.AgentPolicy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AgentRuntimeTest {

  @Test
  void modeParsingAcceptsSynonyms() {
    assertEquals(DetectionMode.OFF, DetectionMode.parse("off"));
    assertEquals(DetectionMode.OFF, DetectionMode.parse("DISABLED"));
    assertEquals(DetectionMode.MONITOR, DetectionMode.parse("record"));
    assertEquals(DetectionMode.MONITOR, DetectionMode.parse(" Observe "));
    assertEquals(DetectionMode.BLOCK, DetectionMode.parse("protect"));
    assertNull(DetectionMode.parse("nonsense"));
    assertNull(DetectionMode.parse(null));
  }

  @Test
  void unsetModePreservesLegacyBehavior() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    assertNull(runtime.mode());
    assertTrue(runtime.detectionEnabled(), "detection on by default");
    assertTrue(runtime.blockingAllowed(), "blocking permitted in legacy mode");
    assertTrue(runtime.isAlgorithmEnabled("sql_userinput"));
  }

  @Test
  void offModeDisablesDetection() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"off\"}");
    assertEquals(DetectionMode.OFF, runtime.mode());
    assertFalse(runtime.detectionEnabled());
    assertFalse(runtime.blockingAllowed());
  }

  @Test
  void monitorModeDetectsButDoesNotBlock() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"monitor\"}");
    assertEquals(DetectionMode.MONITOR, runtime.mode());
    assertTrue(runtime.detectionEnabled());
    assertFalse(runtime.blockingAllowed());
  }

  @Test
  void blockModeAllowsBlocking() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    assertEquals(DetectionMode.BLOCK, runtime.mode());
    assertTrue(runtime.blockingAllowed());
  }

  @Test
  void algorithmToggleSuppressesNamedAlgorithm() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\",\"algorithms\":{\"sql_userinput\":false,\"command\":true}}");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"), "explicitly disabled");
    assertTrue(runtime.isAlgorithmEnabled("command"), "explicitly enabled");
    assertTrue(runtime.isAlgorithmEnabled("xxe"), "absent → enabled");
  }

  @Test
  void revisionIsTracked() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"monitor\",\"revision\":7}");
    assertEquals(7, runtime.revision());
  }

  @Test
  void malformedControlDocumentIsIgnored() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    runtime.apply("not json at all");
    runtime.apply("[1,2,3]");
    // Last good state is retained.
    assertEquals(DetectionMode.BLOCK, runtime.mode());
  }

  @Test
  void onlyACompleteControlObjectWithATopLevelModeChangesTheMode() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    for (String text :
        new String[] {
          "{\"mode\":\"off\"",
          "{\"mode\":\"of",
          "{\"mode\":\"off\",",
          "{\"policy\":{\"mode\":\"off\"}}",
          "{\"algorithms\":[{\"mode\":\"off\"}]}",
          "{\"note\":\"\\\"mode\\\":\\\"off\\\"\"}",
          "{\"mode\":\"sleep\"}",
          "{\"mode\":\"off\"} trailing",
          "{\"mode\":\"off\"}{}",
          "[{\"mode\":\"off\"}]",
          "{\"mode\":\"off\",}",
          "{\"mode\":off}",
          "{'mode':'off'}",
          "",
        }) {
      runtime.apply(text);
      assertEquals(DetectionMode.BLOCK, runtime.mode(), text);
    }
    runtime.apply("{\"policy\":\"{\\\"mode\\\":\\\"block\\\"}\",\"mode\":\"monitor\"}");
    assertEquals(DetectionMode.MONITOR, runtime.mode());
  }

  @Test
  void aDocumentThatIsNotWellFormedJsonOrThatSimpleJsonCannotReadChangesNothing(@TempDir Path dir)
      throws Exception {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.apply("{\"mode\":\"block\"}");
    for (String text :
        new String[] {
          "{\"mode\":\"off\",\"n\":01}",
          "{\"mode\":\"off\",\"n\":.5}",
          "{\"mode\":\"off\",\"n\":1.}",
          "{\"mode\":\"off\",\"s\":\"raw\ttab\"}",
          "{\"mode\":\"off\",\"s\":\"\\u+041\"}",
          "{\"mode\":\"\\u\uFF10\uFF10\uFF16\uFF46ff\"}",
          "\u00A0{\"mode\":\"off\"}",
          "{\"mode\":\"off\"}\u2003",
          // Valid JSON that SimpleJson cannot read: an integer outside long. Unparseable, too.
          "{\"mode\":\"off\",\"revision\":123456789012345678901234567890}",
        }) {
      assertFalse(runtime.apply(text), text);
      assertEquals(DetectionMode.BLOCK, runtime.mode(), text);
    }

    // A file holding a byte that is not UTF-8 is unparseable as well.
    Path file = dir.resolve("control.json");
    AgentRuntime polling = startPolling(file);
    Files.writeString(file, "{\"mode\":\"block\"}");
    polling.reloadIfChanged();
    byte[] head = "{\"mode\":\"off\",\"note\":\"".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] bytes = java.util.Arrays.copyOf(head, head.length + 3);
    bytes[head.length] = (byte) 0xFF;
    bytes[head.length + 1] = '"';
    bytes[head.length + 2] = '}';
    Files.write(file, bytes);
    polling.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, polling.mode(), "malformed UTF-8");
  }

  @Test
  void aControlFileLargerThanTheBoundIsUnparseableAndNoErrorEscapesThePoll(@TempDir Path dir)
      throws Exception {
    Path file = dir.resolve("control.json");
    int bound = 1 << 20;
    Files.writeString(file, "{\"mode\":\"block\"}");
    AgentRuntime runtime = startPolling(file);

    Files.writeString(file, padded("{\"mode\":\"off\"}", bound + 1));
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "one byte over the bound");
    Files.writeString(file, padded("{\"mode\":\"monitor\"}", bound));
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.MONITOR, runtime.mode(), "exactly the bound applies");

    // A sparse 3 GiB file: reading it whole fails with OutOfMemoryError. Only bound + 1 bytes are
    // read, and nothing escapes the poll step.
    try (java.io.RandomAccessFile huge = new java.io.RandomAccessFile(file.toFile(), "rw")) {
      huge.setLength(3L << 30);
    }
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.MONITOR, runtime.mode(), "a 3 GiB file");

    // A policy nested deeply enough to overflow SimpleJson's recursion: the policy is not
    // installed, the rest of the document applies, and the StackOverflowError stays inside.
    int depth = 400_000;
    String policy = "[".repeat(depth) + "]".repeat(depth);
    Files.writeString(file, "{\"mode\":\"off\",\"policy\":\"" + policy + "\"}");
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode());
    assertSame(AgentPolicy.absent(), runtime.policy());
  }

  /**
   * A file system that fails with an Error other than StackOverflowError or OutOfMemoryError. The
   * poll step, which start also runs once before the application starts, keeps it inside.
   */
  @Test
  void anErrorFromTheFileSystemStaysInsideThePollStep(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    Files.writeString(file, "{\"mode\":\"monitor\"}");
    AgentRuntime runtime = startPolling(file);
    assertEquals(DetectionMode.MONITOR, runtime.mode());

    runtime.reloadIfChanged(failingPath());
    assertEquals(DetectionMode.MONITOR, runtime.mode(), "the last good state stays");
    assertFalse(AgentOwnIo.active(), "the own-I/O mark is cleared");
  }

  /** A path whose every method, the lookup of its file system included, throws AssertionError. */
  static Path failingPath() {
    return (Path) java.lang.reflect.Proxy.newProxyInstance(
        Path.class.getClassLoader(),
        new Class<?>[] {Path.class},
        (proxy, method, args) -> {
          throw new AssertionError("file system provider failure in " + method.getName());
        });
  }

  private static String padded(String json, int size) {
    return json + " ".repeat(size - json.length());
  }

  @Test
  void aControlFileReadHalfWrittenIsPickedUpOnceCompleteWithTheSameModificationTime(@TempDir Path dir)
      throws Exception {
    Path file = dir.resolve("control.json");
    FileTime sameTime = FileTime.fromMillis(1_500_000_000_000L);
    writeAt(file, "{\"mode\":\"block\"}", FileTime.fromMillis(1_400_000_000_000L));
    AgentRuntime runtime = startPolling(file);
    assertEquals(DetectionMode.BLOCK, runtime.mode());

    writeAt(file, "{\"mode\":\"off\"", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "a half-written document changes nothing");
    writeAt(file, "{\"mode\":\"off\"}", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "the completed document applies");

    // Content decides, not the modification time: a new document with the same time applies.
    writeAt(file, "{\"mode\":\"monitor\"}", sameTime);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.MONITOR, runtime.mode());
  }

  @Test
  void aMissingControlFileRestoresStartUpSettingsAndAnUnreadableOneKeepsTheLastGoodOnes(@TempDir Path dir)
      throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "no file yet");

    String document =
        "{\"mode\":\"off\",\"algorithms\":{\"sql_userinput\":false},\"revision\":4,"
            + "\"policy\":\"{\\\"version\\\":4}\"}";
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode());
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(4, runtime.revision());
    assertEquals(4, runtime.policy().version());

    // Present but not readable as a document: the daemon replaces the file atomically, so this is
    // transient and the last good settings stay.
    Files.writeString(file, "{\"mode\":\"block\"");
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "truncated content");
    Files.delete(file);
    Files.createDirectory(file);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "a directory in the file's place");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));

    // Removed: every setting taken from the file returns to its start-up value, the policy the
    // file installed included.
    Files.delete(file);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "a missing control file restores the start-up mode");
    assertTrue(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(0, runtime.revision());
    assertSame(AgentPolicy.absent(), runtime.policy(), "the control file's policy is gone");

    // The same document written again applies again, its policy included.
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.OFF, runtime.mode(), "the same document after a removal");
    assertFalse(runtime.isAlgorithmEnabled("sql_userinput"));
    assertEquals(4, runtime.policy().version());
  }

  @Test
  void anIgnoreRuleFromARemovedControlFileStopsSuppressingDetections(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    Detection sql = detection("sql_userinput");
    assertFalse(runtime.policy().evaluate(sql, "").ignored(), "no policy at start-up");

    Files.writeString(
        file,
        "{\"mode\":\"monitor\",\"algorithms\":{\"xxe\":false},"
            + "\"policy\":\"{\\\"rules\\\":[{\\\"algorithm\\\":\\\"sql_userinput\\\","
            + "\\\"action\\\":\\\"ignore\\\"}]}\"}");
    runtime.reloadIfChanged();
    AgentRuntime.ControlState fromFile = runtime.state();
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, fromFile.policySource());
    assertTrue(fromFile.policy().evaluate(sql, "").ignored(), "the control file's ignore rule");

    Files.delete(file);
    runtime.reloadIfChanged();
    AgentRuntime.ControlState restored = runtime.state();
    assertFalse(
        restored.policy().evaluate(sql, fromFile.policyAgentKey()).ignored(),
        "an ignore rule from a deleted control file still suppresses detections");
    assertSame(AgentPolicy.absent(), restored.policy());
    assertEquals(AgentRuntime.PolicySource.NONE, restored.policySource());
    // One snapshot: everything the file set returned together, and the earlier snapshot a hook may
    // still hold is unchanged.
    assertEquals(DetectionMode.BLOCK, restored.mode());
    assertTrue(restored.isAlgorithmEnabled("xxe"));
    assertEquals(DetectionMode.MONITOR, fromFile.mode());
    assertFalse(fromFile.isAlgorithmEnabled("xxe"));
  }

  @Test
  void aDirectCloudPolicyIsNotTheControlFilesToRemove(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    String document = "{\"policy\":\"{\\\"version\\\":4}\"}";
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(4, runtime.policy().version());

    // The direct-cloud client installs later and owns the policy from then on.
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "agent-key");
    assertEquals(AgentRuntime.PolicySource.DIRECT_CLOUD, runtime.state().policySource());
    Files.delete(file);
    runtime.reloadIfChanged();
    assertEquals(9, runtime.policy().version(), "removing the control file keeps the cloud policy");
    assertEquals("agent-key", runtime.state().policyAgentKey());

    // A control file that comes back installs its policy again: the last source to install wins.
    Files.writeString(file, document);
    runtime.reloadIfChanged();
    assertEquals(4, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());
  }

  /**
   * The daemon withdraws a policy by rewriting the control file without {@code policy}. A file
   * with no policy (absent, null or blank) drops the one the file installed, not a direct-cloud one.
   */
  @Test
  void aPolicyTheControlFileNoLongerCarriesStopsSuppressingDetections(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000,mode=block");
    Detection sql = detection("sql_userinput");
    String ignoreSql =
        "\"policy\":\"{\\\"rules\\\":[{\\\"algorithm\\\":\\\"sql_userinput\\\",\\\"action\\\":\\\"ignore\\\"}]}\"";

    String[] withdrawn = {"{\"mode\":\"monitor\",\"revision\":2}", "{\"revision\":3,\"policy\":null}",
        "{\"revision\":4,\"policy\":\" \"}"};
    for (String document : withdrawn) {
      Files.writeString(file, "{\"mode\":\"monitor\",\"revision\":1," + ignoreSql + "}");
      runtime.reloadIfChanged();
      assertTrue(runtime.policy().evaluate(sql, "").ignored(), "the control file's ignore rule");

      Files.writeString(file, document);
      runtime.reloadIfChanged();
      assertFalse(
          runtime.policy().evaluate(sql, "").ignored(),
          "a withdrawn control-file policy still suppresses detections: " + document);
      assertSame(AgentPolicy.absent(), runtime.policy());
      assertEquals(AgentRuntime.PolicySource.NONE, runtime.state().policySource());
      assertEquals(DetectionMode.MONITOR, runtime.mode(), "the rest of the document applies");
    }

    // A direct-cloud policy is not the control file's to withdraw.
    Files.writeString(file, "{\"revision\":5," + ignoreSql + "}");
    runtime.reloadIfChanged();
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "agent-key");
    Files.writeString(file, "{\"revision\":6}");
    runtime.reloadIfChanged();
    assertEquals(9, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.DIRECT_CLOUD, runtime.state().policySource());
  }

  /**
   * Policy text that fails to parse is not recorded as applied. Sequence: control-file policy P,
   * direct-cloud policy Q, control file with policy text that does not parse, control file with P
   * again. The malformed step keeps Q. The last step changes nothing either: P is still the
   * control-file policy last applied, so the file's policy has not changed since Q was installed,
   * and Q, the last policy successfully installed, stays.
   */
  @Test
  void aControlFilePolicyThatFailsToParseIsNotRecordedAsApplied() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    String p = "{\"policy\":\"{\\\"version\\\":4}\"}";
    runtime.apply(p);
    assertEquals(4, runtime.policy().version());
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "agent-key");

    runtime.apply("{\"revision\":2,\"policy\":\"[1]\"}");
    assertEquals(9, runtime.policy().version(), "a policy that does not parse displaced the cloud policy");
    assertEquals(AgentRuntime.PolicySource.DIRECT_CLOUD, runtime.state().policySource());

    runtime.apply(p);
    assertEquals(9, runtime.policy().version(), "a failed parse made the unchanged file policy look new");
    assertEquals("agent-key", runtime.state().policyAgentKey());

    // A policy the file has not carried before still replaces the cloud policy.
    runtime.apply("{\"policy\":\"{\\\"version\\\":5}\"}");
    assertEquals(5, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());
  }

  private static Detection detection(String algorithm) {
    return new Detection(
        Instant.now(), "sql", algorithm, "log", 90, "test", RequestContext.empty(), Map.of());
  }

  @Test
  void classesTheHooksUseFirstAreLoadedWhenTheRuntimeInitialises() throws Exception {
    // A hook must not load a class for the first time: the hooks run inside JDK classes.
    // BootstrapAgent initialises AgentRuntime before it installs the transformer.
    java.net.URL classes = AgentRuntime.class.getProtectionDomain().getCodeSource().getLocation();
    // The shared classes too: the runtime reads its baked settings through io.ohmyrasp.agent.util.BakedProperties.
    java.net.URL shared =
        io.ohmyrasp.agent.util.BakedProperties.class.getProtectionDomain().getCodeSource().getLocation();
    try (IsolatedLoader loader = new IsolatedLoader(classes, shared)) {
      Class.forName(AgentRuntime.class.getName(), true, loader);
      assertTrue(loader.loaded(AgentOwnIo.class.getName()), "AgentOwnIo was not loaded by initialisation");
    }
  }

  /** A class loader that answers whether it has loaded a class. */
  private static final class IsolatedLoader extends java.net.URLClassLoader {
    IsolatedLoader(java.net.URL... classes) {
      super(classes, null);
    }

    boolean loaded(String name) {
      return findLoadedClass(name) != null;
    }
  }

  /**
   * A runtime polling {@code file}, driven by direct {@link AgentRuntime#reloadIfChanged} calls:
   * its poller thread waits a day before its first poll, so it never runs during a test.
   */
  /** A failed start stops the runtime: the poller has ended when stop returns, and no poll changes the state after. */
  @Test
  void stopEndsThePollerAndNoPollPublishesAfterIt(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("control.json");
    Files.writeString(file, "{\"mode\":\"block\"}");
    AgentRuntime runtime = startPolling(file);
    assertEquals(DetectionMode.BLOCK, runtime.mode());
    Thread poller = runtime.pollerThread();
    assertTrue(poller != null && poller.isAlive(), "the start did not start the poller");

    runtime.stop();

    assertFalse(poller.isAlive(), "stop returned while the poller still ran");
    assertNull(runtime.pollerThread());
    Files.writeString(file, "{\"mode\":\"off\"}");
    runtime.reloadIfChanged();
    assertFalse(runtime.apply("{\"mode\":\"monitor\"}"), "a stopped runtime applied a control document");
    Files.delete(file);
    runtime.reloadIfChanged();
    assertEquals(DetectionMode.BLOCK, runtime.mode(), "a poll after stop changed the state");
  }

  /** The direct-cloud client's install into a runtime whose start was undone is refused. */
  @Test
  void aStoppedRuntimeInstallsNoDirectPolicy() {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":3}"), "before");
    runtime.stop();

    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "after");

    assertEquals(3, runtime.policy().version(), "a stopped runtime published a cloud policy");
    assertEquals("before", runtime.state().policyAgentKey());
  }

  /** A stop that runs before start reaches its poller keeps the poller from starting at all. */
  @Test
  void aStopBeforeThePollerStartsKeepsItFromStarting(@TempDir Path dir) {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.stop();
    runtime.start("control=" + dir.resolve("control.json") + ",control_poll_ms=86400000");
    assertNull(runtime.pollerThread(), "a poller started after stop");
  }

  static AgentRuntime startPolling(Path file) {
    AgentRuntime runtime = AgentRuntime.newForTesting();
    runtime.start("control=" + file + ",control_poll_ms=86400000");
    return runtime;
  }

  static void writeAt(Path file, String text, FileTime time) throws Exception {
    Files.writeString(file, text);
    Files.setLastModifiedTime(file, time);
  }

  @Test
  void distributedPolicyIsInstalledOncePerChange() {
    AgentRuntime runtime = AgentRuntime.newForTesting();

    runtime.apply("{\"mode\":\"block\",\"policy\":\"{\\\"version\\\":4}\"}");
    assertEquals(4, runtime.policy().version());
    // A cloud policy installed in between is not replaced by the same control-file policy again.
    runtime.installDirectPolicy(AgentPolicy.parse("{\"version\":9}"), "");
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":4}\"}"); // unchanged policy
    assertEquals(9, runtime.policy().version());
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"{\\\"version\\\":5}\"}"); // changed policy
    assertEquals(5, runtime.policy().version());
    // A policy that does not parse changes nothing.
    runtime.apply("{\"mode\":\"monitor\",\"policy\":\"[1]\"}");
    assertEquals(5, runtime.policy().version());
    assertEquals(AgentRuntime.PolicySource.CONTROL_FILE, runtime.state().policySource());
  }
}
