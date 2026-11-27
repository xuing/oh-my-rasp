package org.apache.jasper.compiler;

/** A stand-in with Jasper's name and method: compiling a JSP runs {@code write}. */
public final class Compiler {
  private Compiler() {}

  public static void compile(Runnable write) {
    write.run();
  }
}
