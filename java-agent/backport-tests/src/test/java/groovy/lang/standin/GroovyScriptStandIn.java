package groovy.lang.standin;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

/** A frame in a {@code groovy.} package, as a Groovy script's launch has: the backports' script_evaluation stack. */
public final class GroovyScriptStandIn {
  private GroovyScriptStandIn() {}

  public static void launch(String... argv) {
    Java8RaspHooks.beforeRuntimeExecArray(argv);
  }
}
