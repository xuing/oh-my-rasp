package io.ohmyrasp.agent.rules.product.c3p0;

/** Apply the c3p0 class policy to resolved data-source and naming types. */
public final class C3p0StreamTypes {
  public static final String PACKAGE_PREFIX = "com.mchange.v2.c3p0.";

  private C3p0StreamTypes() {}

  public static boolean permitsTypeCheck(Class<?> type) {
    return !type.getName().startsWith(PACKAGE_PREFIX) || exposesConnectionOrNaming(type);
  }

  private static boolean exposesConnectionOrNaming(Class<?> type) {
    if (type == null) return false;
    String name = type.getName();
    // The bootstrap-loaded agent need not link the platform's JDBC and naming modules.
    if ("javax.sql.CommonDataSource".equals(name)
        || "javax.naming.Referenceable".equals(name)
        || "javax.naming.spi.ObjectFactory".equals(name)) return true;
    for (Class<?> contract : type.getInterfaces()) {
      if (exposesConnectionOrNaming(contract)) return true;
    }
    return exposesConnectionOrNaming(type.getSuperclass());
  }
}
