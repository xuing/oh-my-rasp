package io.ohmyrasp.agent.rules.product.hessian;

import io.ohmyrasp.agent.rules.product.beanshell.BeanShellTypes;
import io.ohmyrasp.agent.serialization.StreamTypeNames;

/** Class identities are stable across repeated allocations and unload with their defining loader. */
public final class HessianAllocationTypes {
  private HessianAllocationTypes() {}

  private static final ClassValue<Boolean> LISTED = new ClassValue<Boolean>() {
    @Override protected Boolean computeValue(Class<?> selected) {
      if (selected.isArray() || java.lang.reflect.Modifier.isAbstract(selected.getModifiers())) return false;
      if (StreamTypeNames.explicitlyListed(selected.getName()) || ClassLoader.class.isAssignableFrom(selected)) return true;
      for (Class<?> type = selected; type != null; type = type.getSuperclass()) {
        String name = type.getName();
        if (StreamTypeNames.CONFIG_CONTEXT_TYPES.contains(name) || "org.h2.jdbc.JdbcConnection".equals(name)
            || (StreamTypeNames.listed(name) && BeanShellTypes.permitsTypeCheck(type))) return true;
      }
      return false;
    }
  };

  public static boolean listed(Class<?> selected) { return selected != null && LISTED.get(selected); }
}
