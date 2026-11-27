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

  /**
   * The classes the injected calls reach (and the start that turns them on). Each must resolve, through this entry's
   * own loader, to the definition the bootstrap loader makes from the appended JAR.
   */
  static final String[] INJECTED_TARGETS = {
    "io.ohmyrasp.agent.BootstrapAgent",
    "io.ohmyrasp.agent.hook.HookActivation",
    "io.ohmyrasp.agent.hook.OhMyRaspHooks",
    "io.ohmyrasp.agent.hook.DeserializationGuard",
    "io.ohmyrasp.agent.hook.GeneratedLineWrite",
    "io.ohmyrasp.agent.hook.OhMyRaspBlockException",
    "io.ohmyrasp.agent.file.HostDirectory",
  };

  private static void start(String agentArgs, Instrumentation instrumentation) {
    File agentJar = appendSelfToBootstrap(instrumentation);
    if (agentJar != null) {
      requireBootstrapDefined(OhMyRaspAgent.class.getClassLoader(), INJECTED_TARGETS);
    }
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

  /**
   * Throws unless each class, looked up through {@code own} as the injected calls of a class that loader defines
   * would look it up, is the one the bootstrap loader defined. A copy another loader defined first (the agent JAR is
   * also on the application class path and the application used it before an attach) would be the one those calls
   * reach: its activation flag is never turned on, so the hooks would stay inert there while the start reported
   * success. The start fails instead, before anything is started, and the launcher reports it.
   */
  static void requireBootstrapDefined(ClassLoader own, String... classNames) {
    for (String className : classNames) {
      Class<?> found;
      try {
        found = Class.forName(className, false, own);
      } catch (ClassNotFoundException e) {
        throw new IllegalStateException(className + " is not on the bootstrap search after the append", e);
      }
      if (found.getClassLoader() != null) {
        throw new IllegalStateException(className + " is already defined by " + found.getClassLoader()
            + ", not the bootstrap loader: the injected calls would reach that copy, which the start does not turn on");
      }
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
