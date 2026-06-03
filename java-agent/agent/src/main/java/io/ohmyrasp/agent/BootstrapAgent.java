package io.ohmyrasp.agent;

import io.ohmyrasp.agent.asm.HookRegistry;
import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.DeserializationGuard;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import io.ohmyrasp.agent.log.JsonEventLogger;
import java.lang.instrument.Instrumentation;

public final class BootstrapAgent {
  private BootstrapAgent() {}

  public static void start(String agentArgs, Instrumentation instrumentation) {
    HookRegistry hookRegistry = HookRegistry.defaults();
    ControlPlaneClient controlPlane =
        ControlPlaneClient.start(ControlPlaneConfig.load(agentArgs), OhMyRaspHooks::installPolicy);
    JsonEventLogger.get().setControlPlaneClient(controlPlane);
    installCrashReporter(controlPlane);
    DeserializationGuard.install();
    instrumentation.addTransformer(new OhMyRaspTransformer(hookRegistry), true);
    retransformAlreadyLoadedTargets(instrumentation, hookRegistry);
    System.out.println(
        "[OHMYRASP] agent started with ASM transformer, args="
            + (agentArgs == null ? "" : agentArgs));
  }

  private static void installCrashReporter(ControlPlaneClient controlPlane) {
    if (controlPlane == null) {
      return;
    }
    Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
    Thread.setDefaultUncaughtExceptionHandler(
        (thread, throwable) -> {
          controlPlane.submitCrash(thread == null ? "" : thread.getName(), throwable);
          if (previous != null) {
            previous.uncaughtException(thread, throwable);
          }
        });
  }

  private static void retransformAlreadyLoadedTargets(
      Instrumentation instrumentation, HookRegistry hookRegistry) {
    if (!instrumentation.isRetransformClassesSupported()) {
      return;
    }
    for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
      if (!instrumentation.isModifiableClass(loaded)) {
        continue;
      }
      String name = loaded.getName();
      if (hookRegistry.isRetransformTarget(name)) {
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
}
