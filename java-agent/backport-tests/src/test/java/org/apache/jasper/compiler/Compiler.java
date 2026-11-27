package org.apache.jasper.compiler;

import io.ohmyrasp.agent.java8.Java8RaspHooks;
import org.apache.jasper.JspCompilationContext;

/** A stand-in with Jasper's name and the shape of its compile: it writes the file its context names. */
public abstract class Compiler {
  protected JspCompilationContext ctxt;

  public void init(JspCompilationContext ctxt) {
    this.ctxt = ctxt;
  }

  public JspCompilationContext getCompilationContext() {
    return ctxt;
  }

  public void compile() {
    compile(true, false);
  }

  public void compile(boolean compileClass, boolean jspcMode) {
    Java8RaspHooks.beforeFileWrite(ctxt.target());
  }
}
