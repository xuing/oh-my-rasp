package com.xxl.job.core.handler.impl;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class ScriptJobHandler {
  private ScriptJobHandler() {}

  public static void invokeJava11GlueShell() {
    Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "sh",
          "/data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh",
          "",
          "0",
          "0"
        });
  }
}
