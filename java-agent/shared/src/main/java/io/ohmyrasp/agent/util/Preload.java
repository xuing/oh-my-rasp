package io.ohmyrasp.agent.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

/**
 * Loads and initialises, before an agent line registers its first transformer, every class of ours that a hook
 * or a transformer can use: hooks run inside JDK calls, where loading a class for the first time can re-enter
 * the hook. The list is written at build time into the agent JAR (META-INF/ohmyrasp/preload/&lt;module&gt;.txt,
 * by gradle/preload-index.gradle.kts): the module's own classes and the shared ones. It is read from the agent
 * JAR file itself, not through a class loader, so a same-named resource elsewhere cannot replace it.
 */
public final class Preload {
  /** Where the lists are in the agent JAR. */
  public static final String INDEX = "META-INF/ohmyrasp/preload/";

  private Preload() {}

  /**
   * Loads and initialises every class the list of {@code module} names, through {@code loader} (null for the
   * bootstrap loader). Returns how many. Throws when the JAR has no list for the module or a class cannot be
   * loaded or initialised: a line whose classes are not all there must not start.
   */
  public static int classes(File agentJar, String module, ClassLoader loader) throws IOException {
    List<String> names = index(agentJar, module);
    for (int i = 0; i < names.size(); i++) {
      try {
        Class.forName(names.get(i), true, loader);
      } catch (ClassNotFoundException | LinkageError failure) {
        throw new IllegalStateException("cannot load " + names.get(i) + " from " + agentJar + ": " + failure, failure);
      }
    }
    return names.size();
  }

  static List<String> index(File agentJar, String module) throws IOException {
    JarFile jar = new JarFile(agentJar);
    try {
      ZipEntry entry = jar.getEntry(INDEX + module + ".txt");
      if (entry == null) {
        throw new IllegalStateException(agentJar + " has no " + INDEX + module + ".txt");
      }
      List<String> names = new ArrayList<String>();
      BufferedReader reader =
          new BufferedReader(new InputStreamReader(jar.getInputStream(entry), StandardCharsets.UTF_8));
      try {
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
          if (line.length() > 0) {
            names.add(line);
          }
        }
      } finally {
        reader.close();
      }
      return names;
    } finally {
      jar.close();
    }
  }
}
