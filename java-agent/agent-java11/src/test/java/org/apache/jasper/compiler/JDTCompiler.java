package org.apache.jasper.compiler;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class JDTCompiler {
  private JDTCompiler() {}

  public static void writeJava11JspCompilationFile(String path) {
    Java11RaspHooks.beforeFileWrite(path);
  }
}
