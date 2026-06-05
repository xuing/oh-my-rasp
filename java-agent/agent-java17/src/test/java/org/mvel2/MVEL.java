package org.mvel2;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class MVEL {
  private MVEL() {}

  public static void invokeJava17TouchCommand() {
    Java17RaspHooks.beforeRuntimeExecString("touch /tmp/ohmyrasp-unomi-touch-success");
  }
}
