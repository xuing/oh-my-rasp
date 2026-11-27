package io.ohmyrasp.agent;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.jar.JarFile;

public final class OhMyRaspAgent {
  private OhMyRaspAgent() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    start(agentArgs, instrumentation);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    start(agentArgs, instrumentation);
  }

  private static void start(String agentArgs, Instrumentation instrumentation) {
    File agentJar = appendSelfToBootstrap(instrumentation);
    try {
      Class<?> bootstrapAgent = Class.forName("io.ohmyrasp.agent.BootstrapAgent", true, null);
      Method start = bootstrapAgent.getMethod("start", String.class, Instrumentation.class, File.class);
      start.invoke(null, agentArgs, instrumentation, agentJar);
    } catch (InvocationTargetException e) {
      // The start's own failure, not the reflection around it: the launcher reports its message.
      Throwable cause = e.getCause();
      if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      }
      if (cause instanceof Error) {
        throw (Error) cause;
      }
      throw new IllegalStateException("Unable to start OhMyRASP bootstrap agent", e);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Unable to start OhMyRASP bootstrap agent", e);
    }
  }

  /** The agent JAR, appended to the bootstrap search; null when it could not be found or appended. */
  private static File appendSelfToBootstrap(Instrumentation instrumentation) {
    ProtectionDomain domain = OhMyRaspAgent.class.getProtectionDomain();
    CodeSource codeSource = domain == null ? null : domain.getCodeSource();
    URL location = codeSource == null ? null : codeSource.getLocation();
    if (location == null) {
      System.err.println(
          "[OHMYRASP] unable to append agent jar to bootstrap search: missing code source location");
      return null;
    }
    File jarFile;
    try {
      jarFile = new File(location.toURI());
    } catch (URISyntaxException | IllegalArgumentException e) {
      jarFile = new File(location.getPath());
    }
    try {
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(jarFile));
      return jarFile;
    } catch (IOException | RuntimeException e) {
      System.err.println("[OHMYRASP] unable to append agent jar to bootstrap search: " + e);
      return null;
    }
  }
}
