package com.thoughtworks.xstream.core;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class TreeUnmarshaller {
  private TreeUnmarshaller() {}

  public static void invokeJava11ProcessBuilderStart(ProcessBuilder processBuilder) {
    Java11RaspHooks.beforeProcessBuilderStart(processBuilder);
  }
}
