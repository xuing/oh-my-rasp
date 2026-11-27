package io.ohmyrasp.agent.file;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.net.URL;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.catalina.startup.ExpandWar;
import org.apache.catalina.startup.HostConfig;
import org.apache.jasper.JspCompilationContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The Tomcat WAR-unpack and JSP-compile exemptions of the script-write rule rest on evidence an application cannot
 * give by naming a class: the operation and the container class driving it on the stack, defined by one loader that
 * is not a web application's, writing under the container's base directory (catalina.base). The stand-in Tomcat
 * classes of this test tree carry Tomcat's names and methods.
 */
final class ScriptFileWriteTomcatTest {
  private static final String BASE = "/opt/tomcat-base";

  @BeforeEach
  void containerBase() {
    System.setProperty("catalina.base", BASE);
  }

  @AfterEach
  void clear() {
    System.clearProperty("catalina.base");
  }

  /** {@code ScriptFileWrite.protectedWrite(path)} as seen from inside {@code operation}. */
  private static boolean protectedInside(final String path, Operation operation) throws Exception {
    final boolean[] result = new boolean[1];
    operation.run(new Runnable() {
      @Override public void run() {
        result[0] = ScriptFileWrite.protectedWrite(path);
      }
    });
    return result[0];
  }

  private interface Operation {
    void run(Runnable write) throws Exception;
  }

  @Test
  void tomcatUnpackingAWarUnderItsBaseIsLeftAlone() throws Exception {
    String jsp = BASE + "/webapps/ROOT/index.jsp";
    assertTrue(ScriptFileWrite.protectedWrite(jsp), "the same write without the container");
    assertFalse(protectedInside(jsp, new Operation() {
      @Override public void run(Runnable write) {
        HostConfig.deployWAR(write);
      }
    }));
  }

  @Test
  void anUnpackOutsideTheBaseOrWithoutTheDeployerOrInAnotherMethodIsProtected() throws Exception {
    assertTrue(protectedInside("/var/www/html/shell.jsp", new Operation() {
      @Override public void run(Runnable write) {
        HostConfig.deployWAR(write);
      }
    }), "outside catalina.base");
    assertTrue(protectedInside(BASE + "/webapps/ROOT/shell.jsp", new Operation() {
      @Override public void run(Runnable write) {
        ExpandWar.expand(write);
      }
    }), "ExpandWar called without the deployer");
    assertTrue(protectedInside(BASE + "/webapps/ROOT/shell.jsp", new Operation() {
      @Override public void run(Runnable write) {
        HostConfig.copyWAR(write);
      }
    }), "ExpandWar.copy is not the unpack");
    System.clearProperty("catalina.base");
    assertTrue(protectedInside(BASE + "/webapps/ROOT/shell.jsp", new Operation() {
      @Override public void run(Runnable write) {
        HostConfig.deployWAR(write);
      }
    }), "no container base");
  }

  /** A web application that ships classes named like Tomcat's (here defined by a web application loader). */
  @Test
  void classesNamedLikeTomcatsButDefinedByAWebApplicationAreNotTheContainer() throws Exception {
    URL classes = HostConfig.class.getProtectionDomain().getCodeSource().getLocation();
    final WebappClassLoaderBase webapp = new WebappClassLoaderBase(new URL[] {classes}, getClass().getClassLoader());
    try {
      final Class<?> deployer = webapp.loadClass(HostConfig.class.getName());
      assertEquals(webapp, deployer.getClassLoader(), "the web application defined it");
      final Method deploy = deployer.getMethod("deployWAR", Runnable.class);
      assertTrue(protectedInside(BASE + "/webapps/ROOT/shell.jsp", new Operation() {
        @Override public void run(Runnable write) throws Exception {
          deploy.invoke(null, write);
        }
      }));
    } finally {
      webapp.close();
    }
  }

  @Test
  void theJspCompilerWritesItsClassesUnderTheWorkDirectoryOnly() throws Exception {
    Operation compile = new Operation() {
      @Override public void run(Runnable write) {
        JspCompilationContext.compile(write);
      }
    };
    assertFalse(protectedInside(BASE + "/work/Catalina/localhost/ROOT/org/apache/jsp/index_jsp.class", compile));
    assertTrue(protectedInside(BASE + "/webapps/ROOT/WEB-INF/../shell.class", compile), "not under work/");
    assertTrue(protectedInside(BASE + "/webapps/ROOT/shell.jsp", compile), "not a class");
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
}
