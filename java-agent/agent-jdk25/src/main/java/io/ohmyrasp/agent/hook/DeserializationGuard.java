package io.ohmyrasp.agent.hook;

import java.io.ObjectInputFilter;

/** Adds the agent decision at the JDK's class check, after the application factory has selected a filter. */
public final class DeserializationGuard {
  private static final ObjectInputFilter GUARD = DeserializationGuard::check;

  private DeserializationGuard() {}

  /** The stream field stays unchanged. Supply a filter for the duration of the JDK check even on unfiltered streams. */
  public static ObjectInputFilter filterOrGuard(ObjectInputFilter selected) {
    return selected == null ? GUARD : selected;
  }

  /** Invoked at the original checkInput call site, inside the JDK's rejection and exception handling. */
  public static ObjectInputFilter.Status checkInput(ObjectInputFilter selected, ObjectInputFilter.FilterInfo info) {
    ObjectInputFilter.Status status = check(info);
    if (status == ObjectInputFilter.Status.REJECTED || selected == GUARD) return status;
    return selected.checkInput(info);
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
}
