package it.geosolutions.jaiext.jiffle.runtime;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class JiffleIndirectRuntimeImpl {
  private JiffleIndirectRuntimeImpl() {}

  public static void invokeJava8JiffleRuntimeCommand() {
    Java8RaspHooks.beforeRuntimeExecString("id");
  }
}
