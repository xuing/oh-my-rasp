package io.ohmyrasp.agent.rules.product.beanshell;

/** Narrow the BeanShell family rule when the JVM supplies an actual serialization type. */
public final class BeanShellTypes {
  private BeanShellTypes() {}

  public static boolean permitsTypeCheck(Class<?> type) {
    while (type.isArray()) type = type.getComponentType();
    String name = type.getName();
    if (!name.startsWith("bsh.")) return true;
    if ("bsh.This".equals(name) || "bsh.XThis".equals(name) || "bsh.XThis$Handler".equals(name)
        || "bsh.Interpreter".equals(name) || "bsh.NameSpace".equals(name)) return true;
    for (Class<?> cls = type; cls != null; cls = cls.getSuperclass()) {
      if ("bsh.SimpleNode".equals(cls.getName())) return true;
    }
    return false;
  }
}
