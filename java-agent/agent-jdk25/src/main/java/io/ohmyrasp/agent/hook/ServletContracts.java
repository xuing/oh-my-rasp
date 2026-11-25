package io.ohmyrasp.agent.hook;

/** Invoke public servlet contracts even when the container uses a package-private dispatch wrapper. */
final class ServletContracts {
  private ServletContracts() {}

  private static final ClassValue<Class<?>> API = new ClassValue<>() {
    @Override protected Class<?> computeValue(Class<?> type) {
      Class<?> contract = find(type);
      return contract == null ? type : contract;
    }
  };

  static Class<?> of(Object receiver) { return API.get(receiver.getClass()); }

  private static Class<?> find(Class<?> type) {
    if (type == null) return null;
    switch (type.getName()) {
      case "javax.servlet.http.HttpServletRequest", "jakarta.servlet.http.HttpServletRequest",
          "javax.servlet.http.HttpServletResponse", "jakarta.servlet.http.HttpServletResponse":
        return type;
    }
    for (Class<?> iface : type.getInterfaces()) {
      Class<?> match = find(iface);
      if (match != null) return match;
    }
    return find(type.getSuperclass());
  }
}
