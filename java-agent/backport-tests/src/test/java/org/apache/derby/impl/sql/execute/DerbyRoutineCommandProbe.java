package org.apache.derby.impl.sql.execute;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class DerbyRoutineCommandProbe {
  private DerbyRoutineCommandProbe() {}

  public static void invokeJava8IdCommand() {
    Java8RaspHooks.beforeRuntimeExecString("id");
  }

  public static void invokeJava8PasswdCommand() {
    Java8RaspHooks.beforeRuntimeExecArray(new String[] {"sh", "-c", "cat /etc/passwd"});
  }
}
