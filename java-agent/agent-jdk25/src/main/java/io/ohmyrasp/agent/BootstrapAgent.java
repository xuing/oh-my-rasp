package io.ohmyrasp.agent;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.asm.HookRegistry;
import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
import java.lang.instrument.Instrumentation;

public final class BootstrapAgent {
  private BootstrapAgent() {}

  public static void start(String agentArgs, Instrumentation instrumentation) {
    io.ohmyrasp.agent.xml.SystemArchiveOrigins.initialize(instrumentation);
    HookRegistry hookRegistry = HookRegistry.defaults();

    // Local runtime control: detection mode, algorithm switches and the cloud policy the daemon
    // distributes, hot-reloaded from the daemon/operator control file. This is the only
    // coordination the agent needs to run standalone.
    AgentRuntime.get().start(agentArgs);

    // The agent reports events asynchronously to its local spool (tailed by the
    // daemon). Direct cloud communication and heartbeats are off by default —
    // that is the daemon's job now — and suppressed entirely in standalone or
    // locked-config mode, remaining available only for legacy deployments via
    // cloud_direct=true.
    if (!AgentRuntime.get().isDirectCloudDisabled()
        && ControlPlaneConfig.directCloudEnabled(agentArgs)) {
      ControlPlaneClient controlPlane =
          ControlPlaneClient.start(ControlPlaneConfig.load(agentArgs), OhMyRaspHooks::installPolicy);
      if (controlPlane != null) {
        JsonEventLogger.get().setControlPlaneClient(controlPlane);
        installCrashReporter(controlPlane);
      }
    }

    // Hooks run, on any thread, from the moment the transformer is added. Initialise what they use
    // first, so that no hook does: the event logger, which loads its settings, starts its writer
    // thread and registers a shutdown hook, the hooks' static state (DetectorEngine and the request
    // scopes, whose initial value is an empty RequestContext) and the DetectionMode every hook
    // compares against. AgentRuntime was initialised and started above.
    JsonEventLogger.get();
    initialize(OhMyRaspHooks.class);
    initialize(RequestContext.class);
    initialize(DetectionMode.class);
    instrumentation.addTransformer(new OhMyRaspTransformer(hookRegistry), true);
    retransformAlreadyLoadedTargets(instrumentation, hookRegistry);
    String startupMessage =
        "[OHMYRASP] agent started with ASM transformer, standalone="
            + AgentRuntime.get().isStandalone()
            + ", mode="
            + describeMode()
            + ", args="
            + (agentArgs == null ? "" : agentArgs);
    String logTarget = JsonEventLogger.get().logTarget();
    if ("stderr".equals(logTarget)) {
      System.err.println(startupMessage);
    } else if (!"none".equals(logTarget)) {
      System.out.println(startupMessage);
    }
  }

  private static void initialize(Class<?> type) {
    try {
      Class.forName(type.getName(), true, type.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException("Unable to initialise " + type.getName(), e);
    }
  }

  private static String describeMode() {
    DetectionMode mode = AgentRuntime.get().mode();
    return mode == null ? "legacy" : mode.token();
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
    Class<?>[] classes = instrumentation.getAllLoadedClasses();
    var multipartOwners = io.ohmyrasp.agent.http.MultipartFilename.loadedOwners(classes);
    for (Class<?> loaded : classes) {
      if (!instrumentation.isModifiableClass(loaded)) {
        continue;
      }
      String name = loaded.getName();
      if (hookRegistry.isRetransformTarget(name) || multipartOwners.contains(loaded) || JdbcSqlMethod.isJdbcImplementation(loaded)
          || io.ohmyrasp.agent.http.RequestBodyVisitor.loadedTarget(loaded)) {
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
