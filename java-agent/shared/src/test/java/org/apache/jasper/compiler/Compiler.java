package org.apache.jasper.compiler;

import io.ohmyrasp.agent.file.DeploymentWork;
import org.apache.jasper.JspCompilationContext;

/** A stand-in with Jasper's name and the shape of its compile: it writes the file its context names. */
public abstract class Compiler {
  protected JspCompilationContext ctxt;
  private String result;

  public void init(JspCompilationContext ctxt) {
    this.ctxt = ctxt;
  }

  public JspCompilationContext getCompilationContext() {
    return ctxt;
  }

  public String result() {
    return result;
  }

  public void compile() throws Exception {
    compile(true);
  }

  public void compile(boolean compileClass) throws Exception {
    compile(compileClass, false);
  }

  public void compile(boolean compileClass, boolean jspcMode) throws Exception {
    result = DeploymentWork.inside(ctxt.target());
  }
}
