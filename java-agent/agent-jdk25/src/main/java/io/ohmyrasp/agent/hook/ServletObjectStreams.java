package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.util.WeakOwners;
import java.io.ObjectInputStream;

/** Keep the input type of directly servlet-backed streams without reading application bytes. */
final class ServletObjectStreams {
  private static final WeakOwners<String> SOURCES = new WeakOwners<>();
  private static final ClassValue<Boolean> SERVLET_INPUT = new ClassValue<>() {
    @Override protected Boolean computeValue(Class<?> type) {
      for (Class<?> c = type; c != null; c = c.getSuperclass()) {
        if ("javax.servlet.ServletInputStream".equals(c.getName()) || "jakarta.servlet.ServletInputStream".equals(c.getName())) return true;
      }
      return false;
    }
  };
  private ServletObjectStreams() {}
  static void constructed(ObjectInputStream stream, Object input) {
    if (input != null && SERVLET_INPUT.get(input.getClass())) SOURCES.put(stream, input.getClass().getName());
  }
  static String source(ObjectInputStream stream) { return SOURCES.get(stream); }
}
