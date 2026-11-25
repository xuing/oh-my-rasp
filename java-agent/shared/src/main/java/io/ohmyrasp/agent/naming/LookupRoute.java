package io.ohmyrasp.agent.naming;

/** Connect the JDK's routing operand and the provider handoff within one lookup. */
public final class LookupRoute {
  private static final ThreadLocal<LookupRoute> CURRENT = new ThreadLocal<LookupRoute>();
  private final LookupRoute parent;
  private final Object initial;
  private final Object name;
  private final String operation;
  private String url;
  private Object provider;

  private LookupRoute(Object initial, Object name, String operation) {
    this.parent = CURRENT.get();
    this.initial = initial;
    this.name = name;
    this.operation = operation;
  }

  public static String basis(String operation) {
    if ("declared_lookup".equals(operation)) return "lookup_name_only";
    return operation.startsWith("URLContext.") ? "provider_root_lookup" : "url_scheme_selection";
  }

  public static void enter(Object initial, Object name, String operation) {
    CURRENT.set(new LookupRoute(initial, name, operation));
  }

  public static void exit() {
    LookupRoute frame = CURRENT.get();
    if (frame == null || frame.parent == null) CURRENT.remove();
    else CURRENT.set(frame.parent);
  }

  public static String selecting(String url, String scheme, Object initial, Object name) {
    LookupRoute frame = CURRENT.get();
    if (frame == null || frame.initial != initial || frame.name != name || scheme == null
        || !url.regionMatches(scheme.length(), "://", 0, 3)) return null;
    frame.url = url;
    return frame.operation;
  }

  public static void dispatch(Object provider, Object name) {
    LookupRoute frame = CURRENT.get();
    if (frame != null && frame.name == name) frame.provider = provider;
  }

  public static boolean observedAtSelection(Object provider, String url) {
    LookupRoute frame = CURRENT.get();
    if (frame == null || frame.provider != provider || url == null || !url.equals(frame.url)) return false;
    frame.provider = null;
    return true;
  }
}
