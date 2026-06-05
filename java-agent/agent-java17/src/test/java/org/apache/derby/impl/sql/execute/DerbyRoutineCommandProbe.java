package org.apache.derby.impl.sql.execute;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class DerbyRoutineCommandProbe {
  private DerbyRoutineCommandProbe() {}

  public static void invokeJava17IdCommand() {
    Java17RaspHooks.beforeRuntimeExecString("id");
  }
}
