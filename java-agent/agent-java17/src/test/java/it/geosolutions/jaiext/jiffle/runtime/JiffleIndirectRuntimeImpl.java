package it.geosolutions.jaiext.jiffle.runtime;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class JiffleIndirectRuntimeImpl {
  private JiffleIndirectRuntimeImpl() {}

  public static void invokeJava17JiffleRuntimeCommand() {
    Java17RaspHooks.beforeRuntimeExecString("id");
  }
}
