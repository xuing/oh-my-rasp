package org.mvel2;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class MVEL {
  private MVEL() {}

  public static void invokeJava11TouchCommand() {
    Java11RaspHooks.beforeRuntimeExecString("touch /tmp/ohmyrasp-unomi-touch-success");
  }
}
