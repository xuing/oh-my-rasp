package org.apache.jasper.compiler;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

/** A stand-in with Jasper's name and method: compiling a JSP writes its class to {@code path}. */
public final class JDTCompiler {
  private JDTCompiler() {}

  public static void generateClass(String path) {
    Java8RaspHooks.beforeFileWrite(path);
  }
}
