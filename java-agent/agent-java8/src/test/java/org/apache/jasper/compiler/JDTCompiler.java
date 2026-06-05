package org.apache.jasper.compiler;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class JDTCompiler {
  private JDTCompiler() {}

  public static void writeJava8JspCompilationFile(String path) {
    Java8RaspHooks.beforeFileWrite(path);
  }
}
