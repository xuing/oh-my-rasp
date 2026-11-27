package io.ohmyrasp.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The primary line's start with the JVM's real Instrumentation, in a JVM of its own ({@link RealJvmStartMain}):
 * classes the transformer really rewrote keep the injected calls when the start then fails, and those calls must do
 * nothing; and a start during JVM shutdown fails without leaving anything behind.
 */
final class BootstrapAgentRealJvmTest {
  private static final String LISTED = "io.ohmyrasp.agent.hook.HookActivation";

  @TempDir Path work;

  /** The control: the classes loaded during the start are rewritten, and once the start commits the hook blocks. */
  @Test
  void aJndiClassRewrittenDuringAStartThatCommitsBlocksTheRemoteLookup() throws Exception {
    Result result = run("starts");
    assertEquals("started", result.ended);
    assertEquals("false", result.loadedBefore, "InitialContext was loaded before the start: it was not rewritten on load");
    assertEquals("blocked", result.lookup, "the hook injected during the start does not act after the commit");
    assertEquals("true", result.hooksOn);
    assertEquals(1, result.transformers);
  }

  /**
   * The same classes, rewritten while the start ran, after a start that then fails: the injected calls stay in them
   * (removing a transformer does not take code out), and they do nothing: the lookup fails as it does without the
   * agent, no thread of ours is left, and no transformer is registered.
   */
  @Test
  void aStartThatFailsAfterAClassWasRewrittenLeavesThatClassInert() throws Exception {
    Result result = run("fails-after-rewrite");
    assertTrue(result.ended.startsWith("threw IllegalStateException: the application's standard output refuses"),
        result.ended);
    assertEquals("false", result.loadedBefore, "InitialContext was loaded before the start: it was not rewritten on load");
    assertTrue(result.lookup.startsWith("naming javax.naming."), "the rewritten lookup acted: " + result.lookup);
    assertEquals("false", result.hooksOn);
    assertEquals("", result.threads, "threads of ours are still alive after the failed start");
    assertEquals(0, result.transformers, "a transformer is still registered after the failed start");
  }

  /** A start from a shutdown hook fails before it starts anything, and the event logger stays usable. */
  @Test
  void aStartDuringJvmShutdownFailsAndLeavesNothing() throws Exception {
    Result result = run("during-shutdown");
    assertTrue(result.ended.startsWith("threw IllegalStateException: the JVM is shutting down"), result.ended);
    assertTrue(result.ended.endsWith("| logger refused IllegalStateException"),
        "the event logger could not be used or started its writer during shutdown: " + result.ended);
    assertEquals("false", result.hooksOn);
    assertEquals("", result.threads);
    assertEquals(0, result.transformers);
  }

  /**
   * Preloading {@code NetworkHost} must not initialise {@code InetAddress}, which reads {@code jdk.net.hosts.file}
   * once: an application that sets it after the agent started gets its own hosts file, as without the agent.
   */
  @Test
  void aStartThatPreloadsNetworkHostLeavesTheHostsFileSettingToTheApplication() throws Exception {
    Result result = run("hosts-file-after-start", "io.ohmyrasp.agent.net.NetworkHost");
    assertEquals("started", result.ended);
    assertEquals("10.11.12.13", result.lookup, "the application's hosts file was ignored: InetAddress initialised early");
  }

  private record Result(String ended, String lookup, String threads, String hooksOn, int transformers,
      String loadedBefore) {}

  private Result run(String scenario, String... listed) throws Exception {
    Path java = Path.of(System.getProperty("java.home"), "bin", "java");
    File holder = holderJar();
    Process process =
        new ProcessBuilder(
                java.toString(),
                "-Xbootclasspath/a:" + System.getProperty("java.class.path"),
                "-javaagent:" + holder,
                "-cp", holder.toString(),
                "-Dohmyrasp.mode=block",
                "-Dohmyrasp.log=" + work.resolve(scenario + "-events.jsonl"),
                "-Dohmyrasp.control=" + work.resolve(scenario + "-control.json"),
                RealJvmStartMain.class.getName(),
                scenario,
                agentJar(listed).getPath())
            .redirectErrorStream(true)
            .start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    process.getInputStream().transferTo(output);
    assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the JVM did not finish");
    String text = output.toString(StandardCharsets.UTF_8);
    for (String line : text.split("\n")) {
      if (line.startsWith("RESULT\t")) {
        String[] parts = line.split("\t", -1);
        return new Result(parts[1], parts[2], parts[3], parts[4], Integer.parseInt(parts[5]), parts[6].trim());
      }
    }
    throw new AssertionError("no RESULT line from the JVM: " + text);
  }

  /** A JAR that holds no class: its manifest names RealJvmStartMain, which the JVM finds on the bootstrap search. */
  private File holderJar() throws IOException {
    File jar = work.resolve("holder.jar").toFile();
    if (!jar.isFile()) {
      Manifest manifest = new Manifest();
      manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
      manifest.getMainAttributes().putValue("Premain-Class", RealJvmStartMain.class.getName());
      manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
      try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar.toPath()), manifest)) {
        out.flush();
      }
    }
    return jar;
  }

  /** The JAR the start reads its preload list from: the listed classes, and their class files. */
  private File agentJar(String... more) throws IOException {
    java.util.List<String> listed = new java.util.ArrayList<>(java.util.List.of(LISTED));
    listed.addAll(java.util.List.of(more));
    File jar = work.resolve("agent-" + listed.size() + ".jar").toFile();
    if (!jar.isFile()) {
      try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar.toPath()))) {
        out.putNextEntry(new JarEntry("META-INF/ohmyrasp/preload/" + BootstrapAgent.MODULE + ".txt"));
        out.write((String.join("\n", listed) + "\n").getBytes(StandardCharsets.UTF_8));
        out.closeEntry();
        for (String name : listed) {
          String path = name.replace('.', '/') + ".class";
          try (InputStream in = BootstrapAgentRealJvmTest.class.getClassLoader().getResourceAsStream(path)) {
            out.putNextEntry(new JarEntry(path));
            out.write(in.readAllBytes());
            out.closeEntry();
          }
        }
      }
    }
    return jar;
  }
}
