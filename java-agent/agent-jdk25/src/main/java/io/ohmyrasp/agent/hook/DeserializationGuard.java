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
          (current, next) -> composeStreamFilter(previous, current, next));
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

  static ObjectInputFilter composeStreamFilter(
      ObjectInputFilter previous, ObjectInputFilter current, ObjectInputFilter next) {
    if (current == null) {
      // At stream construction the JDK supplies the global filter as next.
      return mergedFilter(mergeDistinct(previous, next));
    }
    // The existing stream filter already includes our guard and the global
    // filter. Keep both when the application adds its stream-specific policy.
    return next == previous ? current : mergeDistinct(current, next);
  }

  private static ObjectInputFilter mergeDistinct(ObjectInputFilter first, ObjectInputFilter second) {
    if (first == null) {
      return second;
    }
    return second == null || first == second ? first : ObjectInputFilter.merge(first, second);
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
    try {
      OhMyRaspHooks.beforeSerialFilterClass(className);
    } catch (OhMyRaspBlockException blocked) {
      return ObjectInputFilter.Status.REJECTED;
    } catch (Throwable unexpected) {
      // A detector error must not override the application's own filters.
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
