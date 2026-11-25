package io.ohmyrasp.agent.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.concurrent.ConcurrentHashMap;

/** Associates evidence with one object's identity without calling application equality methods. */
public final class WeakOwners<T> {
  private final ReferenceQueue<Object> collected = new ReferenceQueue<Object>();
  private final ConcurrentHashMap<Key, T> entries = new ConcurrentHashMap<Key, T>();
  private void drain() {
    Key dead;
    while ((dead = (Key) collected.poll()) != null) entries.remove(dead);
  }
  public T get(Object owner) {
    if (entries.isEmpty()) return null;
    drain();
    return entries.get(new Key(owner, null));
  }
  public T remove(Object owner) {
    if (entries.isEmpty()) return null;
    drain();
    return entries.remove(new Key(owner, null));
  }
  public T putIfAbsent(Object owner, T value) {
    drain();
    T prior = entries.putIfAbsent(new Key(owner, collected), value);
    return prior == null ? value : prior;
  }
  public void put(Object owner, T value) {
    drain();
    entries.put(new Key(owner, collected), value);
  }

  private static final class Key extends WeakReference<Object> {
    private final int hash;
    Key(Object connection, ReferenceQueue<Object> queue) {
      super(connection, queue);
      hash = System.identityHashCode(connection);
    }
    @Override public int hashCode() { return hash; }
    @Override public boolean equals(Object other) {
      if (this == other) return true;
      Object value = get();
      return value != null && other instanceof Key && ((Key) other).get() == value;
    }
  }
}
