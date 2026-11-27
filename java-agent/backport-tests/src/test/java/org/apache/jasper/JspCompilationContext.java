package org.apache.jasper;

import org.apache.jasper.compiler.Compiler;
import org.apache.jasper.compiler.JDTCompiler;

/** A stand-in with Jasper's name: the context that knows a JSP's output directory and drives its compile. */
public final class JspCompilationContext {
  private final String outputDir;
  private String target;

  public JspCompilationContext(String outputDir) {
    this.outputDir = outputDir;
  }

  public String getOutputDir() {
    return outputDir;
  }

  public String target() {
    return target;
  }

  /** Compiles, writing {@code path}. */
  public void compile(String path) {
    target = path;
    Compiler compiler = new JDTCompiler();
    compiler.init(this);
    compiler.compile();
  }
}
