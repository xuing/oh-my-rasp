package io.ohmyrasp.agent.hook;

import java.io.ObjectInputStream;

/** Bind filter checks to the stream the XML-RPC parser actually reads. */
public final class XmlRpcReadScope {
  private static final ThreadLocal<XmlRpcReadScope> ACTIVE = new ThreadLocal<>();
  private final XmlRpcReadScope parent;
  private ObjectInputStream stream;

  private XmlRpcReadScope(XmlRpcReadScope parent) { this.parent = parent; }

  public static void enter() { ACTIVE.set(new XmlRpcReadScope(ACTIVE.get())); }

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

  public static void exit() {
    XmlRpcReadScope active = ACTIVE.get();
    if (active.parent == null) ACTIVE.remove();
    else ACTIVE.set(active.parent);
  }
}
