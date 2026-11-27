package io.ohmyrasp.agent.file;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.hook.HookActivation;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.catalina.startup.ContextConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * The Tomcat WAR-unpack and JSP-compile exemptions of the script-write rule rest on the operation itself, observed as
 * it runs, and on the directory the container's own objects report: the docBase under the Host's appBase that the
 * unpack writes, and the output directory of the JSP's compilation context. The stand-in Tomcat classes of this test
 * tree carry Tomcat's names and descriptors; {@link Container} defines them rewritten by the agent's own visitor, as a
 * container's class loader would hold them. Neither {@code catalina.base} nor a class name on the stack is evidence.
 */
final class ScriptFileWriteTomcatTest {
  private static final String APP_BASE = "/srv/webapps";
  private static final String DOC_BASE = APP_BASE + "/app";
  private static final String OUTPUT_DIR = "/opt/tomcat/work/Catalina/localhost/ROOT/org/apache/jsp/";

  @BeforeEach
  void hooksOn() {
    HookActivation.activate();
  }

  @AfterEach
  void clear() {
    HookActivation.deactivate();
    DeploymentWork.body = DeploymentWork.DECIDE;
    System.clearProperty("catalina.base");
  }

  /** Before a start commits and after a failed one, the calls a rewritten Tomcat class makes open no scope. */
  @Test
  void whileTheHooksAreOffAnUnpackOpensNoScope() throws Exception {
    HookActivation.deactivate();
    final String jsp = DOC_BASE + "/index.jsp";
    DeploymentWork.body = new DeploymentWork.Body() {
      @Override public String run(String path) {
        return String.valueOf(ContainerDeployment.covers(path));
      }
    };
    assertEquals("false", unpack(new Container(getClass().getClassLoader()), "app", jsp));

    HookActivation.activate();
    assertEquals("true", unpack(new Container(getClass().getClassLoader()), "app", jsp), "the control: hooks on");
  }

  /**
   * The hooks turn off while a verified unpack runs (a stop): its exit no longer pops its scope, and nothing reads
   * that scope while they are off. On a thread of its own, since the scope stays on the thread.
   */
  @Test
  void anUnpackTheHooksTurnedOffUnderGrantsNothingAfterwards() throws Exception {
    final String jsp = DOC_BASE + "/index.jsp";
    final String[] seen = new String[2];
    final Throwable[] failure = new Throwable[1];
    Thread thread = new Thread(new Runnable() {
      @Override public void run() {
        try {
          DeploymentWork.body = new DeploymentWork.Body() {
            @Override public String run(String path) {
              String during = String.valueOf(ContainerDeployment.covers(path));
              HookActivation.deactivate();
              return during;
            }
          };
          seen[0] = unpack(new Container(ScriptFileWriteTomcatTest.class.getClassLoader()), "app", jsp);
          seen[1] = String.valueOf(ContainerDeployment.covers(jsp));
        } catch (Throwable thrown) {
          failure[0] = thrown;
        }
      }
    });
    thread.start();
    thread.join();
    if (failure[0] != null) throw new AssertionError(failure[0]);
    assertEquals("true", seen[0], "inside the unpack, while the hooks were on");
    assertEquals("false", seen[1], "after it, with the hooks off");
  }

  @Test
  void aWarUnpackedIntoAnExternalAppBaseIsLeftAlone() throws Exception {
    // A Host whose appBase lies outside catalina.base: the docBase the unpack writes is all the evidence needed.
    String jsp = DOC_BASE + "/index.jsp";
    assertTrue(ScriptFileWrite.protectedWrite(jsp), "the same write without the container");
    ClassLoader container = new Container(getClass().getClassLoader());
    assertEquals("false", unpack(container, "app", jsp));
    assertEquals("false", unpack(container, "app", DOC_BASE + "/admin/./page.jspx"));
    assertTrue(ScriptFileWrite.protectedWrite(jsp), "the exemption ends with the unpack");
  }

  @Test
  void aScriptWrittenOutsideTheDocBaseDuringAGenuineUnpackIsProtected() throws Exception {
    // The container's base directory does not widen the exemption to the rest of it.
    System.setProperty("catalina.base", "/srv");
    ClassLoader container = new Container(getClass().getClassLoader());
    assertEquals("true", unpack(container, "app", APP_BASE + "/other/shell.jsp"), "another docBase of the Host");
    assertEquals("true", unpack(container, "app", DOC_BASE + "/../other/shell.jsp"), "out of the docBase by ..");
    assertEquals("true", unpack(container, "app", APP_BASE + "/shell.jsp"), "the appBase itself");
    assertEquals("true", unpack(container, "app", "/var/www/html/shell.jsp"), "an unrelated web root");
    assertEquals("true", unpack(container, "../../var/www/html", "/var/www/html/shell.jsp"),
        "a pathname that leaves the appBase");
  }

  @Test
  void theUnpackScopeBelongsToItsThreadAndEndsWithTheOperation() throws Exception {
    final String jsp = DOC_BASE + "/index.jsp";
    DeploymentWork.body = new DeploymentWork.Body() {
      @Override public String run(final String path) throws Exception {
        final boolean[] other = new boolean[1];
        Thread thread = new Thread(new Runnable() {
          @Override public void run() {
            other[0] = ScriptFileWrite.protectedWrite(path);
          }
        });
        thread.start();
        thread.join();
        return ScriptFileWrite.protectedWrite(path) + "/" + other[0];
      }
    };
    ClassLoader container = new Container(getClass().getClassLoader());
    assertEquals("false/true", unpack(container, "app", jsp), "a thread the unpack starts has no exemption");

    final IllegalStateException failure = new IllegalStateException("corrupt WAR");
    DeploymentWork.body = new DeploymentWork.Body() {
      @Override public String run(String path) {
        throw failure;
      }
    };
    final ClassLoader loader = container;
    InvocationTargetException thrown = assertThrows(InvocationTargetException.class, new Executable() {
      @Override public void execute() throws Throwable {
        unpack(loader, "app", jsp);
      }
    });
    assertSame(failure, thrown.getCause(), "the container's own exception reaches it unchanged");
    assertFalse(ContainerDeployment.covers(jsp), "the scope ended with the exception");
    assertTrue(ScriptFileWrite.protectedWrite(jsp));
  }

  @Test
  void standInsNamedLikeTomcatWithoutTheObservedOperationAreNotTheContainer() throws Exception {
    // The test loader's own copies are not rewritten: the stack holds ExpandWar.expand under ContextConfig, defined by
    // one loader that is not a web application's, and the write is under catalina.base, which is all main asked for.
    System.setProperty("catalina.base", "/srv");
    assertEquals("true", ContextConfig.fixDocBase(new StandardHost(new File(APP_BASE)),
        new URL("file", "", DOC_BASE + "/index.jsp"), "app"));
  }

  @Test
  void anApplicationCallingTheObserverOrTheUnpackItselfGetsNothing() throws Exception {
    ClassLoader container = new Container(getClass().getClassLoader());
    Class<?> expandWar = container.loadClass(ContainerDeployment.EXPAND_WAR);
    Object host = host(container);
    String jsp = DOC_BASE + "/index.jsp";

    ContainerDeployment.enterWarExpand(expandWar, host, "app");
    try {
      assertFalse(ContainerDeployment.covers(jsp), "the observer called from outside the unpack");
    } finally {
      ContainerDeployment.exit();
    }
    // The genuine, rewritten unpack, called by a class of another loader (here reflectively) instead of the container.
    String direct = (String) expandWar.getMethod("expand", container.loadClass("org.apache.catalina.Host"), URL.class,
        String.class).invoke(null, host, new URL("file", "", jsp), "app");
    assertEquals("true", direct);
  }

  @Test
  void tomcatNamedClassesDefinedByAWebApplicationAreNotTheContainer() throws Exception {
    ClassLoader webapp = new Webapp(getClass().getClassLoader());
    assertEquals("true", unpack(webapp, "app", DOC_BASE + "/index.jsp"), "defined by a web application's loader");
    ClassLoader below = new Container(new WebappClassLoaderBase(new URL[0], getClass().getClassLoader()));
    assertEquals("true", unpack(below, "app", DOC_BASE + "/index.jsp"), "defined below a web application's loader");
  }

  @Test
  void anUnverifiedInnerOperationHidesTheOuterOne() throws Exception {
    final ClassLoader webapp = new Webapp(getClass().getClassLoader());
    final String jsp = DOC_BASE + "/index.jsp";
    DeploymentWork.body = new DeploymentWork.Body() {
      private int depth;

      @Override public String run(String path) throws Exception {
        if (depth > 0) {
          return DeploymentWork.DECIDE.run(path);
        }
        depth++;
        String inner = unpack(webapp, "app", jsp);
        return inner + "/" + DeploymentWork.DECIDE.run(path);
      }
    };
    assertEquals("true/false", unpack(new Container(getClass().getClassLoader()), "app", jsp));
  }

  @Test
  void onlyTheUnpackIsObservedNotTheContainersOtherCopies() throws Exception {
    ClassLoader container = new Container(getClass().getClassLoader());
    Class<?> config = container.loadClass("org.apache.catalina.startup.ContextConfig");
    String copied = (String) config.getMethod("copyDocBase", container.loadClass("org.apache.catalina.Host"),
        URL.class, String.class).invoke(null, host(container), new URL("file", "", DOC_BASE + "/index.jsp"), "app");
    assertEquals("true", copied, "ExpandWar.copy is not the unpack");
  }

  @Test
  void jaspersCompileWritesClassesUnderItsOutputDirectoryOnly() throws Exception {
    System.setProperty("catalina.base", "/opt/tomcat");
    ClassLoader container = new Container(getClass().getClassLoader());
    assertTrue(ScriptFileWrite.protectedWrite(OUTPUT_DIR + "index_jsp.class"), "the same write without the compiler");
    assertEquals("false", compile(container, OUTPUT_DIR, OUTPUT_DIR + "index_jsp.class"));
    assertEquals("false", compile(container, OUTPUT_DIR, OUTPUT_DIR + "index_jsp$Helper.class"));
    assertEquals("true", compile(container, OUTPUT_DIR, OUTPUT_DIR + "shell.jsp"), "not a class");
    assertEquals("true", compile(container, OUTPUT_DIR, "/opt/tomcat/work/Catalina/localhost/ROOT/shell.class"),
        "the work directory, outside this JSP's output directory");
    assertEquals("true", compile(container, OUTPUT_DIR, OUTPUT_DIR + "../../../shell.class"), "out of it by ..");
    assertEquals("true", compile(container, OUTPUT_DIR, "/opt/tomcat/webapps/ROOT/shell.class"), "a web root");
    // A context whose work directory lies outside catalina.base.
    String elsewhere = "/var/cache/tomcat/work/Catalina/localhost/ROOT/org/apache/jsp/";
    assertEquals("false", compile(container, elsewhere, elsewhere + "index_jsp.class"));
    assertEquals("true", compile(new Webapp(getClass().getClassLoader()), OUTPUT_DIR, OUTPUT_DIR + "index_jsp.class"),
        "a Jasper defined by a web application's loader");
  }

  /** The WEB-INF exemption reads the resolved path: a class written through WEB-INF/classes/../.. is not one. */
  @Test
  void aWebInfTraversalIsNotADeploymentArtifact() {
    assertFalse(ScriptFileWrite.protectedWrite("/srv/webapps/ROOT/WEB-INF/classes/com/acme/Report.class"));
    assertTrue(ScriptFileWrite.protectedWrite("/srv/webapps/ROOT/WEB-INF/classes/../../shell.class"));
    assertEquals("/srv/webapps/ROOT/shell.class",
        ScriptFileWrite.resolve("/srv/webapps/ROOT/WEB-INF/classes/../../shell.class"));
    assertEquals("../x/y", ScriptFileWrite.resolve("../x/./y"));
    assertEquals("/a", ScriptFileWrite.resolve("/a/b/.."));
  }

  // ---- the container ------------------------------------------------------------------------------------------

  private static Object host(ClassLoader loader) throws Exception {
    return loader.loadClass("org.apache.catalina.core.StandardHost").getConstructor(File.class)
        .newInstance(new File(APP_BASE));
  }

  /** Tomcat's ContextConfig of {@code loader} unpacking a WAR as {@code pathname} of the Host, writing {@code path}. */
  private static String unpack(ClassLoader loader, String pathname, String path) throws Exception {
    Class<?> config = loader.loadClass("org.apache.catalina.startup.ContextConfig");
    assertSame(loader, config.getClassLoader(), "the loader under test defines the container");
    return (String) config.getMethod("fixDocBase", loader.loadClass("org.apache.catalina.Host"), URL.class,
        String.class).invoke(null, host(loader), new URL("file", "", path), pathname);
  }

  /** Jasper of {@code loader} compiling a JSP whose output directory is {@code outputDir}, writing {@code path}. */
  private static String compile(ClassLoader loader, String outputDir, String path) throws Exception {
    Class<?> context = loader.loadClass("org.apache.jasper.JspCompilationContext");
    Object instance = context.getConstructor(String.class).newInstance(outputDir);
    return (String) context.getMethod("compile", String.class).invoke(instance, path);
  }

  private static boolean tomcat(String name) {
    return (name.startsWith("org.apache.catalina.") && !name.startsWith("org.apache.catalina.loader."))
        || name.startsWith("org.apache.jasper.");
  }

  /** The stand-in's class file, rewritten by {@link ContainerDeploymentVisitor} as every agent line applies it. */
  static byte[] instrumented(String name) throws ClassNotFoundException {
    InputStream in = ScriptFileWriteTomcatTest.class.getClassLoader()
        .getResourceAsStream(name.replace('.', '/') + ".class");
    if (in == null) {
      throw new ClassNotFoundException(name);
    }
    byte[] original;
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] chunk = new byte[8192];
      for (int n; (n = in.read(chunk)) > 0;) {
        out.write(chunk, 0, n);
      }
      in.close();
      original = out.toByteArray();
    } catch (IOException failure) {
      throw new ClassNotFoundException(name, failure);
    }
    ClassReader reader = new ClassReader(original);
    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    final String owner = reader.getClassName();
    reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override public MethodVisitor visitMethod(int access, String method, String descriptor, String signature,
          String[] exceptions) {
        MethodVisitor visitor = super.visitMethod(access, method, descriptor, signature, exceptions);
        return ContainerDeploymentVisitor.wrap(owner, visitor, access, method, descriptor);
      }
    }, ClassReader.EXPAND_FRAMES);
    return writer.toByteArray();
  }

  /** A container's class loader: it defines the Tomcat classes itself, rewritten; the rest come from its parent. */
  static final class Container extends ClassLoader {
    Container(ClassLoader parent) {
      super(parent);
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      if (!tomcat(name)) {
        return super.loadClass(name, resolve);
      }
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          byte[] bytes = instrumented(name);
          loaded = defineClass(name, bytes, 0, bytes.length);
        }
        assertNotNull(loaded);
        return loaded;
      }
    }
  }

  /** A web application's loader that defines classes of Tomcat's names itself, rewritten like the container's. */
  static final class Webapp extends WebappClassLoaderBase {
    Webapp(ClassLoader parent) {
      super(new URL[0], parent);
    }

    @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      if (!tomcat(name)) {
        return super.loadClass(name, resolve);
      }
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          byte[] bytes = instrumented(name);
          loaded = defineClass(name, bytes, 0, bytes.length);
        }
        return loaded;
      }
    }
  }
}
