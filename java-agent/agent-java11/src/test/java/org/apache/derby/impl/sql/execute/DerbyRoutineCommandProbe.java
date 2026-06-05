package org.apache.derby.impl.sql.execute;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class DerbyRoutineCommandProbe {
  private DerbyRoutineCommandProbe() {}

  public static void invokeJava11IdCommand() {
    Java11RaspHooks.beforeRuntimeExecString("id");
  }
}
