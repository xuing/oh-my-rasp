package com.xxl.job.core.handler.impl;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class ScriptJobHandler {
  private ScriptJobHandler() {}

  public static void invokeJava17GlueShell() {
    Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "sh",
          "/data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh",
          "",
          "0",
          "0"
        });
  }
}
