package cn.keking.service;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class OfficePluginManager {
  private OfficePluginManager() {}

  public static void invokeJava17OfficeCountCommand() {
    Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "ps -ef | grep soffice.bin |grep -v grep | wc -l"});
  }

  public static void invokeJava17OfficeKillCommand() {
    Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "sh", "-c", "ps -ef | grep soffice.bin | grep -v grep | awk '{print \"kill -9 \"$2}' | sh"
        });
  }
}
