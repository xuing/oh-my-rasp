package io.ohmyrasp.agent.jmx;

/** Select the receiver for the legacy JMX reader's display conversion without invoking application code. */
public final class JmxAttributeDisplay {
  private JmxAttributeDisplay() {}

  public static Object receiver(Object value, boolean repair) {
    if (!repair || value == null || value instanceof String || value instanceof Boolean || value instanceof Character
        || value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long
        || value instanceof Float || value instanceof Double) return value;
    return System.identityHashCode(value) + "@" + value.getClass().getName();
  }
}
