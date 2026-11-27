package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.rules.product.beanshell.BeanShellTypes;
import io.ohmyrasp.agent.rules.product.c3p0.C3p0StreamTypes;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

/** Adds the agent decision at the JDK's class check, after the application factory has selected a filter. */
public final class DeserializationGuard {
  private static final ObjectInputFilter GUARD = DeserializationGuard::check;

  private DeserializationGuard() {}

  /** The stream field stays unchanged. Supply a filter for the duration of the JDK check even on unfiltered streams. */
  public static ObjectInputFilter filterOrGuard(ObjectInputFilter selected) {
    if (HookActivation.inactive()) return selected;
    return selected == null ? GUARD : selected;
  }

  /** Compatibility entry point for hooks without the stream receiver. */
  public static ObjectInputFilter.Status checkInput(ObjectInputFilter selected, ObjectInputFilter.FilterInfo info) {
    if (HookActivation.inactive()) return inactiveCheck(selected, info);
    return checkInput(selected, info, null);
  }

  /** Invoked inside the JDK's rejection and exception handling with the stream being checked. */
  public static ObjectInputFilter.Status checkInput(ObjectInputFilter selected, ObjectInputFilter.FilterInfo info,
      ObjectInputStream stream) {
    if (HookActivation.inactive()) return inactiveCheck(selected, info);
    ObjectInputFilter.Status status = check(info, stream);
    if (status == ObjectInputFilter.Status.REJECTED || selected == GUARD) return status;
    return selected.checkInput(info);
  }

  /** What the JDK's own check does without the agent: the selected filter decides; the guard alone decides nothing. */
  private static ObjectInputFilter.Status inactiveCheck(ObjectInputFilter selected, ObjectInputFilter.FilterInfo info) {
    return selected == null || selected == GUARD ? ObjectInputFilter.Status.UNDECIDED : selected.checkInput(info);
  }

  static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
    return check(info, null);
  }

  private static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info, ObjectInputStream stream) {
    Class<?> serialClass = info == null ? null : info.serialClass();
    // An array descriptor or allocation does not establish the presence of any
    // component instance. Leave array policy (including length limits) to the
    // application filter; ordinary object elements have their own class checks.
    try {
      if (serialClass == null || serialClass.isArray() || !BeanShellTypes.permitsTypeCheck(serialClass)
          || !C3p0StreamTypes.permitsTypeCheck(serialClass)) return ObjectInputFilter.Status.UNDECIDED;
      return check(serialClass.getName(), stream);
    } catch (LinkageError | SecurityException unavailable) {
      return ObjectInputFilter.Status.UNDECIDED;
    }
  }

  static ObjectInputFilter.Status check(String className) {
    return check(className, null);
  }

  private static ObjectInputFilter.Status check(String className, ObjectInputStream stream) {
    if (className == null || className.isBlank()) {
      return ObjectInputFilter.Status.UNDECIDED;
    }
    try {
      OhMyRaspHooks.beforeSerialFilterClass(className, stream);
    } catch (OhMyRaspBlockException blocked) {
      return ObjectInputFilter.Status.REJECTED;
    } catch (Throwable unexpected) {
      // A detector error must not override the application's own filters.
    }
    return ObjectInputFilter.Status.UNDECIDED;
  }
}
