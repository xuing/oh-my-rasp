package io.ohmyrasp.agent;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.asm.HookRegistry;
import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import io.ohmyrasp.agent.hook.Warmup;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
import io.ohmyrasp.agent.util.Preload;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.List;

public final class BootstrapAgent {
  /** The module whose preload list this line reads (META-INF/ohmyrasp/preload/&lt;module&gt;.txt, written by the build). */
  static final String MODULE = "agent-jdk25";

  private BootstrapAgent() {}

  /**
   * Starts the primary line. {@code agentJar} is the JAR the entry class appended to the bootstrap search. Every
   * class of ours its preload list names is loaded and initialised before the transformer is registered, so no
   * hook or transformer loads one for the first time inside an instrumented call, where loading can re-enter the
   * hook. A missing list or JAR, a class that is not there or fails to initialise, and any failure after the
   * transformer was registered fail the start: the transformer is removed and what this call started (the
   * control-file poller, the event writer, the control-plane client) is stopped, so the launcher's start-failed
   * report holds and the JVM goes on with no hook added by this start and no thread of ours.
   */
  public static void start(String agentArgs, Instrumentation instrumentation, java.io.File agentJar) {
    if (agentJar == null) {
      throw new IllegalStateException("the agent JAR is not on the bootstrap search: no hook is installed");
    }
    // What can fail without a trace comes first, while there is nothing to undo.
    List<String> preload;
    try {
      preload = Preload.verified(agentJar, MODULE);
    } catch (java.io.IOException e) {
      throw new IllegalStateException("cannot read the preload list of " + agentJar, e);
    }
    Started started = new Started();
    try {
      begin(agentArgs, instrumentation, agentJar, preload, started);
    } catch (RuntimeException | Error failure) {
      started.undo(instrumentation, failure);
      throw failure;
    }
  }

  /** What one start did that a failed start must undo. */
  private static final class Started {
    boolean runtime;
    boolean logger;
    ControlPlaneClient controlPlane;
    Thread.UncaughtExceptionHandler handlerBefore;
    boolean handlerReplaced;
    ClassFileTransformer transformer;

    void undo(Instrumentation instrumentation, Throwable failure) {
      if (transformer != null) {
        try {
          instrumentation.removeTransformer(transformer);
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (handlerReplaced) {
        Thread.setDefaultUncaughtExceptionHandler(handlerBefore);
      }
      if (controlPlane != null) {
        try {
          JsonEventLogger.get().setControlPlaneClient(null);
          controlPlane.close();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (logger) {
        try {
          JsonEventLogger.get().stop();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (runtime) {
        try {
          AgentRuntime.get().stop();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
    }
  }

  private static void begin(
      String agentArgs, Instrumentation instrumentation, java.io.File agentJar, List<String> preload, Started started) {
    io.ohmyrasp.agent.xml.SystemArchiveOrigins.initialize(instrumentation);
    HookRegistry hookRegistry = HookRegistry.defaults();

    // Local runtime control: detection mode, algorithm switches and the cloud policy the daemon
    // distributes, hot-reloaded from the daemon/operator control file. This is the only
    // coordination the agent needs to run standalone.
    started.runtime = AgentRuntime.get().start(agentArgs);

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
        started.controlPlane = controlPlane;
        // The logger exists from here on, and so does the thread it may start.
        started.logger = started.runtime;
        JsonEventLogger.get().setControlPlaneClient(controlPlane);
        installCrashReporter(controlPlane, started);
      }
    }

    // Hooks run, on any thread, from the moment the transformer is added. Initialise what they use
    // first, so that no hook does: the event logger, which loads its settings, starts its writer
    // thread and registers a shutdown hook, the hooks' static state (DetectorEngine and the request
    // scopes, whose initial value is an empty RequestContext) and the DetectionMode every hook
    // compares against. AgentRuntime was initialised and started above.
    started.logger = started.runtime;
    JsonEventLogger.get();
    initialize(OhMyRaspHooks.class);
    initialize(RequestContext.class);
    initialize(DetectionMode.class);
    // Then every other class of ours that a hook or the transformer can use, from the JAR's list. The classes
    // above came first because they read the settings AgentRuntime resolved from the agent arguments.
    Preload.load(preload, agentJar, BootstrapAgent.class.getClassLoader());
    // And one pass of the hooks every request runs, so what only running code does (linking lambdas, the JDK's
    // stream classes) happens here and not on the first request's thread.
    Warmup.run();
    ClassFileTransformer transformer = new OhMyRaspTransformer(hookRegistry);
    instrumentation.addTransformer(transformer, true);
    started.transformer = transformer;
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

  private static void installCrashReporter(ControlPlaneClient controlPlane, Started started) {
    if (controlPlane == null) {
      return;
    }
    Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
    started.handlerBefore = previous;
    started.handlerReplaced = true;
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
      if (hookRegistry.isRetransformTarget(name) || multipartOwners.contains(loaded) || JdbcSqlMethod.isJdbcImplementation(loaded)) {
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
