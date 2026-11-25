package org.elasticsearch.common.mvel2;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class MVEL {
  private MVEL() {}

  public static void invokeJava8TouchCommand() {
    Java8RaspHooks.beforeRuntimeExecString("touch /tmp/ohmyrasp-es-3120-success");
  }
}
