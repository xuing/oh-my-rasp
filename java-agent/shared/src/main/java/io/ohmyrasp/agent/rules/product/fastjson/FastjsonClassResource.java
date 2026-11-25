package io.ohmyrasp.agent.rules.product.fastjson;

import java.util.Locale;

/** Classify the resource operand passed by Fastjson to ClassLoader.getResourceAsStream. */
public final class FastjsonClassResource {
  private FastjsonClassResource() {}

  public static String mechanism(String resource) {
    if (resource == null) return null;
    String name = resource.trim().toLowerCase(Locale.ROOT);
    if (name.startsWith("http://")) return "http";
    if (name.startsWith("https://")) return "https";
    if (name.startsWith("jar:http://")) return "jar:http";
    if (name.startsWith("jar:https://")) return "jar:https";
    if (name.startsWith("jar:file:/proc/self/fd/")) return "jar:file:proc-fd";
    return null;
  }
}
