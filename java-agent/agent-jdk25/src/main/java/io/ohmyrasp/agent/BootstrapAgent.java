package io.ohmyrasp.agent;

import io.ohmyrasp.agent.sql.JdbcSqlMethod;
import io.ohmyrasp.agent.asm.HookRegistry;
import io.ohmyrasp.agent.asm.OhMyRaspTransformer;
import io.ohmyrasp.agent.control.ControlPlaneClient;
import io.ohmyrasp.agent.control.ControlPlaneConfig;
import io.ohmyrasp.agent.hook.HookActivation;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import io.ohmyrasp.agent.hook.Warmup;
import io.ohmyrasp.agent.hookmiss.HookMisses;
import io.ohmyrasp.agent.log.JsonEventLogger;
import io.ohmyrasp.agent.model.RequestContext;
import io.ohmyrasp.agent.runtime.AgentRuntime;
import io.ohmyrasp.agent.runtime.DetectionMode;
import io.ohmyrasp.agent.util.Preload;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;

public final class BootstrapAgent {
  /** The module whose preload list this line reads (META-INF/ohmyrasp/preload/&lt;module&gt;.txt, written by the build). */
  static final String MODULE = "agent-jdk25";

  // The one start this JVM makes, whichever entry calls start: NONE until one claims it, then STARTING, then
  // STARTED or FAILED for good. Guarded by LIFECYCLE. This class is defined once, by the bootstrap loader, so the
  // claim holds for every entry, the launcher's and one that bypasses it.
  private static final Object LIFECYCLE = new Object();
  private static final int NONE = 0;
  private static final int STARTING = 1;
  private static final int STARTED = 2;
  private static final int FAILED = 3;
  private static int state = NONE;

  private BootstrapAgent() {}

  /**
   * Starts the primary line. {@code agentJar} is the JAR the entry class appended to the bootstrap search.
   *
   * <p>One start per JVM: a second call, concurrent or later, from any entry, throws and touches nothing.
   *
   * <p>Every class of ours its preload list names is loaded and initialised before the transformer is registered,
   * so no hook or transformer loads one for the first time inside an instrumented call, where loading can re-enter
   * the hook. The hooks the transformer injects stay inert ({@link HookActivation}) until the start commits, its
   * last step; the hook-miss report's worker, the cloud client's I/O and the crash reporter start only after that.
   * A failure before the commit (a missing list or JAR, a class that is not there or fails to initialise, the JVM
   * shutting down, anything after the transformer was registered) undoes the start: the hooks stay off, the
   * transformer is removed, the classes it retransformed are retransformed again without it, and what this call
   * started (the control-file poller, the event writer and its shutdown hook) is stopped without writing anything,
   * so the launcher's start-failed report holds and the JVM goes on with no active hook and no thread of ours.
   * Code the transformer already injected stays in the classes it rewrote; it does nothing.
   */
  public static void start(String agentArgs, Instrumentation instrumentation, java.io.File agentJar) {
    claim();
    boolean committed = false;
    try {
      if (agentJar == null) {
        throw new IllegalStateException("the agent JAR is not on the bootstrap search: no hook is installed");
      }
      requireNotShuttingDown();
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
      committed = true;
      started.commit();
    } finally {
      synchronized (LIFECYCLE) {
        state = committed ? STARTED : FAILED;
      }
    }
  }

  /** Claims the JVM's one start; throws when a start is running or has run, from this entry or another. */
  private static void claim() {
    synchronized (LIFECYCLE) {
      if (state != NONE) {
        throw new IllegalStateException("the primary line was already "
            + (state == STARTING ? "being started" : state == STARTED ? "started" : "started once and failed")
            + " in this JVM: this start does nothing");
      }
      state = STARTING;
    }
  }

  /** Throws when the JVM has begun to shut down: the JVM refuses a shutdown hook then, and a start has no use. */
  private static void requireNotShuttingDown() {
    Thread probe = new Thread("ohmyrasp-shutdown-probe");
    try {
      Runtime.getRuntime().addShutdownHook(probe);
    } catch (IllegalStateException shuttingDown) {
      throw new IllegalStateException("the JVM is shutting down: the agent does not start", shuttingDown);
    }
    Runtime.getRuntime().removeShutdownHook(probe);
  }

  /** What one start did that a failed start must undo, recorded before each step can fail. */
  static final class Started {
    AgentRuntime runtime;
    JsonEventLogger logger;
    boolean hookMisses;
    ControlPlaneClient controlPlane;
    ClassFileTransformer transformer;
    final List<Class<?>> retransformed = new ArrayList<>();

    /**
     * The start committed: the hooks act from now on. Then, each on its own and none able to fail the start, the
     * hook-miss worker, the cloud client's registration and heartbeats, and the crash reporter.
     */
    void commit() {
      HookActivation.activate();
      // The hooks are on: nothing below may throw out of start, which the launcher would report as a failed start
      // with hooks active.
      try {
        if (hookMisses) {
          HookMisses.release();
        }
        if (controlPlane != null) {
          startCloudReporting();
        }
      } catch (Throwable ignored) {
        // Whatever failed here is not the start's.
      }
    }

    private void startCloudReporting() {
      try {
        // The logger sees the client only once its I/O is scheduled; a refused start leaves the logger without it.
        controlPlane.startReporting();
        logger.setControlPlaneClient(controlPlane);
      } catch (Throwable refused) {
        try {
          logger.setControlPlaneClient(null);
        } catch (Throwable ignored) {
          // Nothing more to undo.
        }
        try {
          controlPlane.close();
        } catch (Throwable ignored) {
          // Closed as far as it can be.
        }
        try {
          System.err.println("[OHMYRASP] direct cloud reporting did not start: " + refused);
        } catch (Throwable ignored) {
          // A console the application broke does not fail a start that committed.
        }
        return;
      }
      try {
        installCrashReporter(controlPlane);
      } catch (Throwable refused) {
        // Crashes are not reported to the cloud; everything else is.
      }
    }

    /**
     * Undoes what the start did, each step on its own: a failing step is added to {@code failure} as suppressed
     * and the next still runs. The hooks are turned off first and the workers are stopped before the compensating
     * retransformations, which can wait on other agents' transformers; nothing here writes an event or waits on
     * output.
     */
    void undo(Instrumentation instrumentation, Throwable failure) {
      HookActivation.deactivate();
      if (hookMisses) {
        try {
          HookMisses.stop();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (transformer != null) {
        try {
          instrumentation.removeTransformer(transformer);
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (controlPlane != null) {
        try {
          controlPlane.close();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (logger != null) {
        try {
          logger.cancel();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      if (runtime != null) {
        try {
          runtime.stop();
        } catch (RuntimeException | Error other) {
          failure.addSuppressed(other);
        }
      }
      // Last, because it can run other agents' transformers and stall: by now no worker of ours is left running
      // for it to hold up. Best effort: the classes this start retransformed get their bytecode back without this
      // transformer. A class first loaded during the start, and a method running when it was rewritten, keep the
      // inert calls.
      if (transformer != null) {
        for (Class<?> rewritten : retransformed) {
          try {
            instrumentation.retransformClasses(rewritten);
          } catch (Throwable ignored) {
            // The calls it holds stay inert.
          }
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
    AgentRuntime runtime = AgentRuntime.get();
    if (!runtime.start(agentArgs)) {
      throw new IllegalStateException("the agent runtime was started before this start: nothing is installed");
    }
    started.runtime = runtime;

    // The agent reports events asynchronously to its local spool (tailed by the daemon). Its writer thread and
    // shutdown hook start here; when the JVM is already shutting down this throws and nothing of it started.
    JsonEventLogger logger = JsonEventLogger.get();
    started.logger = logger;
    logger.start();

    // Direct cloud communication and heartbeats are off by default — that is the daemon's job now — and
    // suppressed entirely in standalone or locked-config mode, remaining available only for legacy deployments
    // via cloud_direct=true. The client is prepared here and sends nothing until the start commits.
    if (!runtime.isDirectCloudDisabled() && ControlPlaneConfig.directCloudEnabled(agentArgs)) {
      started.controlPlane =
          ControlPlaneClient.prepare(ControlPlaneConfig.load(agentArgs), OhMyRaspHooks::installPolicy);
    }

    started.hookMisses = io.ohmyrasp.agent.log.HookMissLines.start();
    // Hooks run, on any thread, once the start commits. Initialise what they use first, so that no hook does: the
    // hooks' static state (DetectorEngine and the request scopes, whose initial value is an empty RequestContext)
    // and the DetectionMode every hook compares against. AgentRuntime and the logger were started above.
    initialize(HookActivation.class);
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
    started.transformer = transformer;
    instrumentation.addTransformer(transformer, true);
    retransformAlreadyLoadedTargets(instrumentation, hookRegistry, started.retransformed);
    String startupMessage =
        "[OHMYRASP] agent started with ASM transformer, standalone="
            + runtime.isStandalone()
            + ", mode="
            + describeMode()
            + ", args="
            + (agentArgs == null ? "" : agentArgs);
    String logTarget = logger.logTarget();
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

  /**
   * Reports a thread's uncaught exception to the cloud and hands it on to the handler that was there. Installed only
   * after the start committed, so a failed start never replaces the JVM-wide handler and never has to restore it.
   */
  private static void installCrashReporter(ControlPlaneClient controlPlane) {
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
      Instrumentation instrumentation, HookRegistry hookRegistry, List<Class<?>> retransformed) {
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
        // Recorded first: a retransformation that fails half-way may still have rewritten the class.
        retransformed.add(loaded);
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
