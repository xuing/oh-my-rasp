package io.ohmyrasp.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A start of the primary line that fails leaves no transformer registered and no thread of ours behind, whichever
 * step failed: the launcher reports the failure and the JVM goes on as if the agent had not been attached.
 * Each scenario starts the line in a JVM of its own (see {@link BootstrapAgentFailureMain}); "started" is the control
 * that shows the check can see a transformer and the threads when the start succeeds. No thread whose name starts
 * with {@code ohmyrasp-} may outlive a failed start, the hook-miss writer included, and a failed start leaves the
 * hook-miss report off and writes no hook-miss line, even when a class loaded during it was one.
 */
final class BootstrapAgentFailureTest {
  private static final String LIST = "META-INF/ohmyrasp/preload/" + BootstrapAgent.MODULE + ".txt";
  private static final String EXPLODING = BootstrapAgentFailureMain.ExplodingInit.class.getName();
  // A class every list holds; an empty list fails the start.
  private static final String LISTED = io.ohmyrasp.agent.runtime.DetectionMode.class.getName();

  @TempDir Path work;

  @Test
  void aStartThatSucceedsRegistersOneTransformerAndStartsTheThreads() throws Exception {
    Result result = run("started", jarWith(List.of(LISTED)));
    assertTrue(result.ended.equals("started"), result.ended);
    assertEquals(1, result.transformers);
    assertTrue(result.threads.contains("ohmyrasp-control-poller"), result.threads);
    assertTrue(result.threads.contains("ohmyrasp-event-writer"), result.threads);
  }

  @Test
  void aHookMissDuringAStartThatSucceedsIsWrittenOnceTheStartCommitted() throws Exception {
    Result result = run("miss-then-starts", jarWith(List.of(LISTED)));
    assertEquals("started", result.ended);
    assertTrue(result.hookMissWritten, "the hook miss loaded during the start was not written after it");
    assertTrue(result.reportOn);
  }

  @Test
  void aHookMissDuringAStartThatFailsIsDroppedWithTheReportAndLeavesNoThread() throws Exception {
    Result result = run("miss-then-fails", jarWith(List.of(LISTED)));
    assertFails(result, "the JVM refuses to list its classes");
  }

  @Test
  void aJarWithoutAListFailsBeforeAnythingStarts() throws Exception {
    Result result = run("no-list", jarWith(null));
    assertFails(result, "has no META-INF/ohmyrasp/preload/agent-jdk25.txt");
  }

  @Test
  void aJarWithAnEmptyListFailsBeforeAnythingStarts() throws Exception {
    Result result = run("empty-list", jarWith(List.of()));
    assertFails(result, "has an empty META-INF/ohmyrasp/preload/agent-jdk25.txt");
  }

  /**
   * The undo retransforms the classes the start rewrote, which runs other agents' transformers and can stall: it
   * does so last, after the event writer, the poller and the cloud client are stopped. The fake Instrumentation holds
   * the undo's retransform until our threads are gone (at most 3 s) and records which were alive.
   */
  @Test
  void theUndoStopsItsThreadsBeforeItRetransforms() throws Exception {
    Result result = run("fails-after-retransform", jarWith(List.of(LISTED)));
    assertFails(result, "modifiability cannot be read");
    assertEquals(2, result.retransforms, "the start and its undo each retransform the class once");
    assertEquals("", result.aliveDuringUndoRetransform,
        "threads of ours were still running while the undo retransformed");
  }

  /** Two starts that bypass the launcher, at once: exactly one starts, the other is refused and registers nothing. */
  @Test
  void twoConcurrentStartsStartOnce() throws Exception {
    Result result = run("concurrent", jarWith(List.of(LISTED)));
    assertTrue(result.ended.startsWith("started + threw IllegalStateException: the primary line was already "),
        result.ended);
    assertEquals(1, result.transformers, "the refused start registered a transformer");
    assertTrue(result.threads.contains("ohmyrasp-event-writer"), result.threads);
  }

  /** The launcher does not retry a failed start; a start that bypasses it does not either. */
  @Test
  void aStartAfterAFailedStartIsRefused() throws Exception {
    Result result = run("again-after-failure", jarWith(List.of(LISTED)), jarWith(null));
    assertFails(result, "the primary line was already started once and failed in this JVM");
  }

  @Test
  void anUnreadableJarFailsBeforeAnythingStarts() throws Exception {
    Path notAJar = Files.writeString(work.resolve("broken.jar"), "this is not a ZIP file");
    Result result = run("unreadable", notAJar.toFile());
    assertFails(result, "cannot read the preload list");
  }

  @Test
  void aListedClassTheJarDoesNotHoldFailsBeforeAnythingStarts() throws Exception {
    Result result = run("missing-class", jarWith(List.of("io.ohmyrasp.agent.NoSuchClass")));
    assertFails(result, "holds no io/ohmyrasp/agent/NoSuchClass.class");
  }

  @Test
  void noJarToStartFromFailsBeforeAnythingStarts() throws Exception {
    Result result = run("no-jar", jarWith(List.of(LISTED)));
    assertFails(result, "not on the bootstrap search");
  }

  @Test
  void aClassThatFailsToInitialiseStopsWhatTheStartStarted() throws Exception {
    Result result = run("init-failure", jarWith(List.of(EXPLODING)));
    assertFails(result, "cannot load " + EXPLODING);
  }

  @Test
  void aFailureAfterTheTransformerIsRegisteredRemovesItAndStopsWhatTheStartStarted() throws Exception {
    Result result = run("fails-after-transformer", jarWith(List.of(LISTED)));
    assertFails(result, "the JVM refuses to list its classes");
  }

  private static void assertFails(Result result, String reason) {
    assertTrue(result.ended.startsWith("threw "), "the start did not fail: " + result.ended);
    assertTrue(result.ended.contains(reason), "expected '" + reason + "' in: " + result.ended);
    assertEquals(0, result.transformers, "a transformer is still registered after a failed start");
    assertEquals("", result.threads, "threads of ours are still alive after a failed start");
    assertFalse(result.hookMissWritten, "a failed start wrote a hook-miss line");
    assertFalse(result.reportOn, "the hook-miss report is still on after a failed start");
    assertFalse(result.ended.contains("Unable to start"), result.ended);
  }

  /** A JAR holding the listed classes' own class files and, when {@code list} is not null, the list itself. */
  private File jarWith(List<String> list) throws IOException {
    File jar = Files.createTempFile(work, "agent", ".jar").toFile();
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar.toPath()))) {
      if (list != null) {
        put(out, LIST, String.join("\n", list).concat(list.isEmpty() ? "" : "\n").getBytes(StandardCharsets.UTF_8));
        for (String name : list) {
          String path = name.replace('.', '/') + ".class";
          try (InputStream in = BootstrapAgentFailureTest.class.getClassLoader().getResourceAsStream(path)) {
            if (in != null) {
              put(out, path, in.readAllBytes());
            }
          }
        }
      }
    }
    return jar;
  }

  private static void put(OutputStream out, String name, byte[] bytes) throws IOException {
    JarOutputStream jar = (JarOutputStream) out;
    jar.putNextEntry(new JarEntry(name));
    jar.write(bytes);
    jar.closeEntry();
  }

  private record Result(String ended, int transformers, String threads, boolean hookMissWritten, boolean reportOn,
      int retransforms, String aliveDuringUndoRetransform) {}

  private Result run(String scenario, File jar, File... more) throws Exception {
    Path java = Path.of(System.getProperty("java.home"), "bin", "java");
    java.util.List<String> command = new java.util.ArrayList<>(List.of(
        java.toString(),
        "-cp", System.getProperty("java.class.path"),
        "-Dohmyrasp.log=" + work.resolve(scenario + "-events.jsonl"),
        "-Dohmyrasp.control=" + work.resolve(scenario + "-control.json"),
        BootstrapAgentFailureMain.class.getName(),
        scenario,
        jar.getPath()));
    for (File extra : more) {
      command.add(extra.getPath());
    }
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    process.getInputStream().transferTo(output);
    assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the JVM did not finish");
    String text = output.toString(StandardCharsets.UTF_8);
    for (String line : text.split("\n")) {
      if (line.startsWith("RESULT\t")) {
        String[] parts = line.split("\t", -1);
        return new Result(parts[1], Integer.parseInt(parts[2]), parts[3], Boolean.parseBoolean(parts[4]),
            Boolean.parseBoolean(parts[5]), Integer.parseInt(parts[6]), parts[7]);
      }
    }
    throw new AssertionError("no RESULT line from the JVM: " + text);
  }
}
