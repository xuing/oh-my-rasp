package org.apache.axis2.context.externalize;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class SafeObjectInputStream {
  private SafeObjectInputStream() {}

  public static void invokeJava11ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java11RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
