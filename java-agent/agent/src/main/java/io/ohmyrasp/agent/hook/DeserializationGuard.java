package io.ohmyrasp.agent.hook;

import java.io.ObjectInputFilter;

public final class DeserializationGuard {
  private DeserializationGuard() {}

  public static void install() {
    try {
      ObjectInputFilter.Config.setSerialFilter(DeserializationGuard::check);
    } catch (IllegalStateException alreadyConfigured) {
      if (Boolean.getBoolean("ohmyrasp.debug")) {
        System.err.println("[OHMYRASP] global ObjectInputFilter already configured");
      }
    }
  }

  private static ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
    Class<?> serialClass = info.serialClass();
    if (serialClass != null) {
      OhMyRaspHooks.beforeDeserializationClass(serialClass.getName());
    }
    return Boolean.getBoolean("ohmyrasp.block")
        ? ObjectInputFilter.Status.REJECTED
        : ObjectInputFilter.Status.UNDECIDED;
  }
}
