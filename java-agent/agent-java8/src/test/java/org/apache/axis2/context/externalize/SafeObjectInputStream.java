package org.apache.axis2.context.externalize;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class SafeObjectInputStream {
  private SafeObjectInputStream() {}

  public static void invokeJava8ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java8RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
