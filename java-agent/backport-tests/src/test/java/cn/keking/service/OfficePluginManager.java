package cn.keking.service;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class OfficePluginManager {
  private OfficePluginManager() {}

  public static void invokeJava8OfficeCountCommand() {
    Java8RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "ps -ef | grep soffice.bin |grep -v grep | wc -l"});
  }

  public static void invokeJava8OfficeKillCommand() {
    Java8RaspHooks.beforeRuntimeExecArray(
        new String[] {
          "sh", "-c", "ps -ef | grep soffice.bin | grep -v grep | awk '{print \"kill -9 \"$2}' | sh"
        });
  }
}
