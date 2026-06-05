package org.apache.jasper.compiler;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class JDTCompiler {
  private JDTCompiler() {}

  public static void writeJava17JspCompilationFile(String path) {
    Java17RaspHooks.beforeFileWrite(path);
  }
}
