package it.geosolutions.jaiext.jiffle.runtime;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class JiffleIndirectRuntimeImpl {
  private JiffleIndirectRuntimeImpl() {}

  public static void invokeJava11JiffleRuntimeCommand() {
    Java11RaspHooks.beforeRuntimeExecString("id");
  }
}
