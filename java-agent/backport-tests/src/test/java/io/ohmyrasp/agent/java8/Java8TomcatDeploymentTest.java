package io.ohmyrasp.agent.java8;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Tomcat's WAR unpack and Jasper's JSP compile, rewritten by this line's own file transformer, as the scopes the
 * script-write rule reads: a write under the docBase the unpack writes, or a class under the JSP's output directory,
 * is left alone; another script write during the same operation, or the same write without it, is decided by the rule.
 * The stand-ins of this test tree carry Tomcat's names and descriptors; shared's ScriptFileWriteTomcatTest has the
 * rule's other cases.
 */
final class Java8TomcatDeploymentTest {
  private static final String OUTPUT_DIR = "/usr/local/tomcat/work/Catalina/localhost/ROOT/org/apache/jsp/";

  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("catalina.base");
  }

  private static Path log() throws IOException {
    Path log = Files.createTempFile("ohmyrasp-java8-tomcat", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    return log;
  }

  @Test
  void tomcatsOwnUnpackIntoAnExternalAppBaseAndItsJspClassesAreLeftAlone() throws Exception {
    Path log = log();
    Transformed container = new Transformed(getClass().getClassLoader());
    unpack(container, "/srv/webapps", "app", "/srv/webapps/app/index.jsp");
    compile(container, OUTPUT_DIR, OUTPUT_DIR + "index_jsp.class");
    assertFalse(Files.exists(log), "Tomcat's own writes were reported");

    Java8RaspHooks.beforeFileWrite("/srv/webapps/app/index.jsp");
    assertTrue(new String(Files.readAllBytes(log), StandardCharsets.UTF_8)
        .contains("\"algorithm\":\"java8_file_script_write\""), "the same write outside the unpack");
  }

  @Test
  void aScriptWrittenElsewhereDuringTheOperationIsDecidedByTheRule() throws Exception {
    System.setProperty("catalina.base", "/srv");
    Transformed container = new Transformed(getClass().getClassLoader());
    String[] writes = {"/srv/webapps/other/shell.jsp", "/srv/webapps/app/../shell.jsp", "/var/www/html/shell.jsp"};
    for (String write : writes) {
      Path log = log();
      unpack(container, "/srv/webapps", "app", write);
      assertTrue(Files.exists(log), write);
    }
    String[] classes = {OUTPUT_DIR + "shell.jsp", "/usr/local/tomcat/work/Catalina/localhost/ROOT/shell.class"};
    for (String write : classes) {
      Path log = log();
      compile(container, OUTPUT_DIR, write);
      assertTrue(Files.exists(log), write);
    }
  }

  @Test
  void standInsTheTransformerDidNotRewriteAreNotTheContainer() throws Exception {
    // The test loader's own, unrewritten copies: the names on the stack are not evidence.
    System.setProperty("catalina.base", "/srv");
    Path log = log();
    org.apache.catalina.startup.ContextConfig.fixDocBase(
        new org.apache.catalina.core.StandardHost(new File("/srv/webapps")),
        new URL("file", "", "/srv/webapps/app/stand-in.jsp"), "app");
    assertTrue(Files.exists(log));
  }

  @Test
  void theFileTransformerRewritesOnlyTheUnpackAndTheCompilerBase() throws Exception {
    Java8FileTransformer transformer = new Java8FileTransformer();
    assertNotNull(transformer.transform(null, "org/apache/catalina/startup/ExpandWar", null, null,
        bytes("org.apache.catalina.startup.ExpandWar")));
    assertNotNull(transformer.transform(null, "org/apache/jasper/compiler/Compiler", null, null,
        bytes("org.apache.jasper.compiler.Compiler")));
    assertNull(transformer.transform(null, "org/apache/catalina/startup/ContextConfig", null, null,
        bytes("org.apache.catalina.startup.ContextConfig")));
    assertNull(transformer.transform(null, "org/apache/jasper/compiler/JDTCompiler", null, null,
        bytes("org.apache.jasper.compiler.JDTCompiler")));
  }

  private static void unpack(ClassLoader loader, String appBase, String pathname, String path) throws Exception {
    Class<?> config = loader.loadClass("org.apache.catalina.startup.ContextConfig");
    assertSame(loader, config.getClassLoader());
    Object host = loader.loadClass("org.apache.catalina.core.StandardHost").getConstructor(File.class)
        .newInstance(new File(appBase));
    config.getMethod("fixDocBase", loader.loadClass("org.apache.catalina.Host"), URL.class, String.class)
        .invoke(null, host, new URL("file", "", path), pathname);
  }

  private static void compile(ClassLoader loader, String outputDir, String path) throws Exception {
    Class<?> context = loader.loadClass("org.apache.jasper.JspCompilationContext");
    Object instance = context.getConstructor(String.class).newInstance(outputDir);
    context.getMethod("compile", String.class).invoke(instance, path);
  }

  static byte[] bytes(String name) throws ClassNotFoundException {
    InputStream in = Java8TomcatDeploymentTest.class.getClassLoader()
        .getResourceAsStream(name.replace('.', '/') + ".class");
    if (in == null) {
      throw new ClassNotFoundException(name);
    }
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] chunk = new byte[8192];
      for (int n; (n = in.read(chunk)) > 0;) {
        out.write(chunk, 0, n);
      }
      in.close();
      return out.toByteArray();
    } catch (IOException failure) {
      throw new ClassNotFoundException(name, failure);
    }
  }

  /** A container's class loader: it defines the Tomcat stand-ins itself, through this line's file transformer. */
  static final class Transformed extends ClassLoader {
    private final Java8FileTransformer transformer = new Java8FileTransformer();

    Transformed(ClassLoader parent) {
      super(parent);
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      if (!name.startsWith("org.apache.catalina.") && !name.startsWith("org.apache.jasper.")) {
        return super.loadClass(name, resolve);
      }
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          byte[] original = bytes(name);
          byte[] rewritten = transformer.transform(this, name.replace('.', '/'), null, null, original);
          byte[] defined = rewritten == null ? original : rewritten;
          loaded = defineClass(name, defined, 0, defined.length);
        }
        return loaded;
      }
    }
  }
}
