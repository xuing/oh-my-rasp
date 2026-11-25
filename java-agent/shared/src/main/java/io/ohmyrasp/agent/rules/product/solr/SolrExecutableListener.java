package io.ohmyrasp.agent.rules.product.solr;

import java.util.List;

/** Process launch observed in the Solr listener implementation. */
public final class SolrExecutableListener {
  private static final String OWNER = "org.apache.solr.core.RunExecutableListener";

  private SolrExecutableListener() {}

  public static boolean onStack(StackTraceElement[] stack) {
    for (StackTraceElement frame : stack) {
      if (OWNER.equals(frame.getClassName())) return true;
    }
    return false;
  }

  public static String frame(List<String> stack) {
    if (stack != null) {
      for (String name : stack) {
        if (name != null && OWNER.equals(name.replace('/', '.'))) return name;
      }
    }
    return null;
  }
}
