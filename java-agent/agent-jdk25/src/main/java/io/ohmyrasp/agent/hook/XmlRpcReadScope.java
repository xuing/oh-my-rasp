package io.ohmyrasp.agent.hook;

import java.io.ObjectInputStream;

/** Bind filter checks to the stream the XML-RPC parser actually reads. */
public final class XmlRpcReadScope {
  private static final ThreadLocal<XmlRpcReadScope> ACTIVE = new ThreadLocal<>();
  private final XmlRpcReadScope parent;
  private ObjectInputStream stream;

  private XmlRpcReadScope(XmlRpcReadScope parent) { this.parent = parent; }

  /** Opens the scope of one parse; returns it as the token {@link #exit} takes, or null while the hooks are off. */
  public static Object enter() {
    if (HookActivation.inactive()) return null;
    XmlRpcReadScope scope = new XmlRpcReadScope(ACTIVE.get());
    ACTIVE.set(scope);
    return scope;
  }

  static void reading(ObjectInputStream stream) {
    XmlRpcReadScope active = ACTIVE.get();
    if (active != null) active.stream = stream;
  }

  static boolean reads(ObjectInputStream stream) {
    if (stream == null) return false;
    for (XmlRpcReadScope active = ACTIVE.get(); active != null; active = active.parent) {
      if (active.stream == stream) return true;
    }
    return false;
  }

  /** Closes the scope {@code token} opened: the thread's scope is its parent again. Null opened none. */
  public static void exit(Object token) {
    if (token == null) return;
    XmlRpcReadScope parent = ((XmlRpcReadScope) token).parent;
    if (parent == null) ACTIVE.remove();
    else ACTIVE.set(parent);
  }
}
