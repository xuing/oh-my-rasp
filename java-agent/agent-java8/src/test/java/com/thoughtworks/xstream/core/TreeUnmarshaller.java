package com.thoughtworks.xstream.core;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class TreeUnmarshaller {
  private TreeUnmarshaller() {}

  public static void invokeJava8ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java8RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
