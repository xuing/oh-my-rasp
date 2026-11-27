package org.apache.jasper;

/** A stand-in with Jasper's name: the context that drives a JSP compile. */
public final class JspCompilationContext {
  private JspCompilationContext() {}

  public static void compile(Runnable write) {
    org.apache.jasper.compiler.Compiler.compile(write);
  }
}
