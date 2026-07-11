package io.ohmyrasp.agent.hook;

import java.io.ObjectInputFilter;

/**
 * Installs a JVM-wide {@link ObjectInputFilter} that rejects known-dangerous
 * deserialization gadget classes while leaving every benign class untouched.
 *
 * <p>Two properties matter for correctness:
 *
 * <ul>
 *   <li><b>Selective</b> — only classes the detector considers dangerous are
 *       {@code REJECTED}; everything else (ArrayList, String, application DTOs,
 *       …) stays {@code UNDECIDED}, so ordinary deserialization (HTTP sessions,
 *       RMI, caches) keeps working even in block mode. Rejecting every class was
 *       the original bug — it broke all Java deserialization once blocking was
 *       enabled.
 *   <li><b>Composable</b> — if the application (or the {@code jdk.serialFilter}
 *       system property) already installed a filter, OhMyRasp's check runs first
 *       and delegates to the pre-existing filter on {@code UNDECIDED} instead of
 *       silently giving up.
 * </ul>
 *
 * <p>The guard is fail-safe: any unexpected error while checking a class yields
 * {@code UNDECIDED} and never propagates into the deserializing application.
 */
public final class DeserializationGuard {
  private DeserializationGuard() {}

  public static void install() {
    ObjectInputFilter previous = currentSerialFilter();
    ObjectInputFilter merged = mergedFilter(previous);
    try {
      ObjectInputFilter.Config.setSerialFilter(merged);
      return;
    } catch (IllegalStateException alreadyConfigured) {
      // A JVM-wide filter is already installed and setSerialFilter may only be
      // called once. Compose at the filter-factory level instead of giving up.
    } catch (Throwable unexpected) {
      debug("serial filter install failed: " + unexpected);
      return;
    }
    installViaFactory(previous);
  }

  private static void installViaFactory(ObjectInputFilter previous) {
    try {
      ObjectInputFilter.Config.setSerialFilterFactory(
          (current, next) -> {
            // `current` is the JVM-wide filter already in effect (falling back to
            // the one we captured); keep OhMyRasp's check in front of it and of
            // any stream-specific filter.
            ObjectInputFilter base = mergedFilter(current != null ? current : previous);
            return next == null ? base : chain(base, next);
          });
    } catch (Throwable unexpected) {
      // The factory is also one-shot and rejects installation once a stream has
      // been filtered. Nothing more we can safely do; the app's filter stays.
      debug("serial filter factory install failed: " + unexpected);
    }
  }

  /**
   * Composes OhMyRasp's {@link #check} with a pre-existing filter: our check runs
   * first, and only its {@code UNDECIDED} results fall through to {@code previous}.
   */
  static ObjectInputFilter mergedFilter(ObjectInputFilter previous) {
    return info -> {
      ObjectInputFilter.Status status = check(info);
      if (status != ObjectInputFilter.Status.UNDECIDED) {
        return status;
      }
      return previous == null ? ObjectInputFilter.Status.UNDECIDED : previous.checkInput(info);
    };
  }

  private static ObjectInputFilter chain(ObjectInputFilter first, ObjectInputFilter second) {
    return info -> {
      ObjectInputFilter.Status status = first.checkInput(info);
      if (status != ObjectInputFilter.Status.UNDECIDED) {
        return status;
      }
      return second.checkInput(info);
    };
  }

  static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
    Class<?> serialClass = info == null ? null : info.serialClass();
    // FilterInfo is consulted for stream metadata too (array length, depth, …);
    // only a concrete class is relevant to us — defer everything else.
    return serialClass == null
        ? ObjectInputFilter.Status.UNDECIDED
        : check(serialClass.getName());
  }

  static ObjectInputFilter.Status check(String className) {
    if (className == null || className.isBlank()) {
      return ObjectInputFilter.Status.UNDECIDED;
    }
    boolean dangerous;
    try {
      dangerous = OhMyRaspHooks.isDangerousDeserialization(className);
    } catch (Throwable unexpected) {
      // Fail-safe: never let the guard break deserialization on our account.
      return ObjectInputFilter.Status.UNDECIDED;
    }
    // Record the attempt through the normal hook (telemetry + request-scoped
    // policy/block). A request-scoped block decision surfaces as an exception,
    // which we translate into REJECTED; nothing else may escape into the app.
    try {
      OhMyRaspHooks.beforeDeserializationClass(className);
    } catch (OhMyRaspBlockException blocked) {
      return ObjectInputFilter.Status.REJECTED;
    } catch (Throwable unexpected) {
      // An unexpected hook failure must not break deserialization; fall through.
    }
    // Enforce at the serial-filter level even without an active request (RMI,
    // caches): reject known-dangerous gadget classes when blocking is enabled.
    // Benign classes always fall through to UNDECIDED.
    if (dangerous && OhMyRaspHooks.blockingEnabled()) {
      return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
  }

  private static ObjectInputFilter currentSerialFilter() {
    try {
      return ObjectInputFilter.Config.getSerialFilter();
    } catch (Throwable unexpected) {
      return null;
    }
  }

  private static void debug(String message) {
    if (Boolean.getBoolean("ohmyrasp.debug")) {
      System.err.println("[OHMYRASP] " + message);
    }
  }
}
