package org.apache.axis2.context.externalize;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class SafeObjectInputStream {
  private SafeObjectInputStream() {}

  public static void invokeJava17ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java17RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
