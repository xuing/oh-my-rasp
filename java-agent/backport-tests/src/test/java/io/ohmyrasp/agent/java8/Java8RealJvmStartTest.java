package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The line's start with the JVM's real Instrumentation and its packaged agent JAR, in a JVM of its own
 * ({@link Java8RealJvmStartMain}): the hooks the transformers inject act only once the start has committed, a hook an
 * application thread enters during a start that then fails never acts and never throws, and one start per JVM.
 */
final class Java8RealJvmStartTest {
  @TempDir Path work;

  /** The control: a start that commits. A hook entered during the start does nothing; after the commit it acts. */
  @Test
  void aHookEnteredDuringTheStartDoesNothingAndActsOnceTheStartCommitted() throws Exception {
    String[] result = run("commits");
    assertEquals("started", result[0]);
    assertEquals("returned", result[1], "a hook acted before the start committed");
    assertEquals("returned", result[2]);
    // In block mode the command rule blocks it: the hook acts.
    assertEquals("true/threw " + Java8RaspBlockException.class.getName(), result[3],
        "the hook does not act after the commit");
    assertEquals("true", result[5]);
  }

  /**
   * The start fails after every transformer was registered and the targets retransformed, while an application thread
   * runs a rewritten process start. The thread ends as it would without the agent (no exception from the agent), the
   * hook never acted for it, nothing of ours runs afterwards and no transformer is left.
   */
  @Test
  void aStartUndoneWhileAnApplicationThreadIsInAHookLeavesItAndTheJvmUntouched() throws Exception {
    String[] result = run("fails-during-start");
    assertTrue(result[0].startsWith("threw IllegalStateException: the application's standard error refuses"),
        result[0]);
    assertEquals("returned", result[1], "a hook acted during a start that then failed");
    assertEquals("returned", result[2], "the application thread did not end as it would without the agent");
    assertEquals("false/returned", result[3], "a hook acts after the failed start");
    assertEquals("", result[4], "threads of ours are alive after the failed start");
    assertEquals("false", result[5]);
    assertEquals("0", result[6], "a transformer is still registered after the failed start");
  }

  /** A second entry, after a start that committed, throws and registers nothing. */
  @Test
  void aSecondEntryChangesNothing() throws Exception {
    String[] result = run("second-entry");
    assertEquals("started", result[0]);
    assertTrue(result[7].startsWith("threw IllegalStateException: [OHMYRASP] the backport line was already started"),
        result[7]);
    String counts = result[7].substring(result[7].indexOf("| transformers ") + "| transformers ".length());
    String[] beforeAfter = counts.split(" -> ");
    assertEquals(beforeAfter[0], beforeAfter[1], "the second entry registered transformers");
    assertNotEquals("0", beforeAfter[0]);
  }

  /**
   * Every line the runtime writes to the spool is UTF-8, whatever the JVM's default charset: the daemon splits the
   * spool on newline bytes and decodes each line as UTF-8. The detection goes through the writer thread and is still
   * queued when the JVM exits: the shutdown hook lets the writer drain it.
   */
  @Test
  void theSpoolIsUtf8WhateverTheDefaultCharsetAndTheWriterDrainsAtExit() throws Exception {
    Path log = work.resolve("events.jsonl");
    List<String> command = new ArrayList<String>(Arrays.asList(java(), "-Dfile.encoding=ISO-8859-1",
        "-Dohmyrasp.java8.log=" + log, "-Dohmyrasp.control=none", "-cp", System.getProperty("java.class.path"),
        Java8RealJvmStartMain.class.getName(), "spool-charset", log.toString()));
    String[] result = result(command);
    assertEquals("ISO-8859-1", result[0], "the child JVM did not take the default charset");
    String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(Files.readAllBytes(log))).toString();
    String[] lines = text.split(System.lineSeparator());
    assertEquals(3, lines.length, text);
    assertTrue(lines[0].contains("café") && lines[0].contains("-agent-start"), lines[0]);
    assertTrue(text.contains("\"message\":\"café\""), "the queued detection was not drained at exit: " + text);
    assertTrue(text.contains("/opt/café.jar"), text);
  }

  private String[] run(String scenario) throws Exception {
    String agentJar = System.getProperty("ohmyrasp.test.agentJar");
    assertTrue(agentJar != null && new File(agentJar).isFile(), "the line's agent JAR is not built: " + agentJar);
    File testClasses = new File(Java8RealJvmStartMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    File holder = holderJar();
    List<String> command = new ArrayList<String>(Arrays.asList(java(), "-javaagent:" + holder,
        "-cp", agentJar + File.pathSeparator + testClasses,
        "-Dohmyrasp.mode=block", "-Dohmyrasp.java8.log=stderr",
        "-Dohmyrasp.control=" + work.resolve(scenario + "-control.json"),
        Java8RealJvmStartMain.class.getName(), scenario));
    return result(command);
  }

  private static String java() {
    return new File(new File(System.getProperty("java.home"), "bin"), "java").getPath();
  }

  private static String[] result(List<String> command) throws Exception {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    InputStream in = process.getInputStream();
    byte[] buffer = new byte[8192];
    for (int n = in.read(buffer); n >= 0; n = in.read(buffer)) {
      output.write(buffer, 0, n);
    }
    assertTrue(process.waitFor(120, TimeUnit.SECONDS), "the JVM did not finish");
    String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
    for (String line : text.split("\n")) {
      if (line.startsWith("RESULT\t")) {
        String[] parts = line.substring("RESULT\t".length()).split("\t", -1);
        for (int i = 0; i < parts.length; i++) {
          parts[i] = parts[i].trim();
        }
        return parts;
      }
    }
    throw new AssertionError("no RESULT line from the JVM: " + text);
  }

  /** A JAR that holds no class: its manifest names Java8RealJvmStartMain, which the JVM finds on the class path. */
  private File holderJar() throws IOException {
    File jar = work.resolve("holder.jar").toFile();
    if (!jar.isFile()) {
      Manifest manifest = new Manifest();
      manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
      manifest.getMainAttributes().putValue("Premain-Class", Java8RealJvmStartMain.class.getName());
      manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
      JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar.toPath()), manifest);
      out.close();
    }
    return jar;
  }
}
