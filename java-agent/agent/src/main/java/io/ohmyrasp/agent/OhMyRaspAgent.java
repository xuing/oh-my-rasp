package io.ohmyrasp.agent;

import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.DeserializationGuard;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
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
    ControlPlaneClient controlPlane = ControlPlaneClient.start(ControlPlaneConfig.load(agentArgs));
    JsonEventLogger.get().setControlPlaneClient(controlPlane);
    appendSelfToBootstrap(instrumentation);
    DeserializationGuard.install();
    instrumentation.addTransformer(new OhMyRaspTransformer(), true);
    retransformAlreadyLoadedTargets(instrumentation);
    System.out.println("[OHMYRASP] agent started with ASM transformer, args=" + (agentArgs == null ? "" : agentArgs));
  }

  private static void appendSelfToBootstrap(Instrumentation instrumentation) {
    String path = OhMyRaspAgent.class.getProtectionDomain().getCodeSource().getLocation().getPath();
    try {
      instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(new File(path)));
    } catch (IOException | RuntimeException e) {
      System.err.println("[OHMYRASP] unable to append agent jar to bootstrap search: " + e);
    }
  }

  private static void retransformAlreadyLoadedTargets(Instrumentation instrumentation) {
    if (!instrumentation.isRetransformClassesSupported()) {
      return;
    }
    for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
      if (!instrumentation.isModifiableClass(loaded)) {
        continue;
      }
      String name = loaded.getName();
      if (isBootstrapTarget(name) || "jakarta.servlet.http.HttpServlet".equals(name)) {
        try {
          instrumentation.retransformClasses(loaded);
        } catch (Throwable throwable) {
          if (Boolean.getBoolean("ohmyrasp.debug")) {
            System.err.println("[OHMYRASP] unable to retransform " + name + ": " + throwable);
          }
        }
      }
    }
  }

  private static boolean isBootstrapTarget(String name) {
    return name.equals("java.lang.ProcessBuilder")
        || name.equals("java.io.FileInputStream")
        || name.equals("java.io.FileOutputStream")
        || name.equals("java.io.File")
        || name.equals("java.nio.file.Files")
        || name.equals("java.net.URL")
        || name.equals("java.net.InetAddress")
        || name.equals("javax.naming.InitialContext")
        || name.equals("com.sun.org.apache.xerces.internal.impl.XMLEntityManager");
  }
}
