package cn.keking.service;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class OfficePluginManager {
  private OfficePluginManager() {}

  public static void invokeJava11OfficeCountCommand() {
    Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "ps -ef | grep soffice.bin |grep -v grep | wc -l"});
  }

  public static void invokeJava11OfficeKillCommand() {
    Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "sh", "-c", "ps -ef | grep soffice.bin | grep -v grep | awk '{print \"kill -9 \"$2}' | sh"
        });
  }
}
