package com.thoughtworks.xstream.core;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class TreeUnmarshaller {
  private TreeUnmarshaller() {}

  public static void invokeJava17ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java17RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
