package org.apache.solr.core;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class RunExecutableListener {
  private RunExecutableListener() {}

  public static void invokeJava11TouchCommand() {
    Java11RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "touch /tmp/ohmyrasp-solr12629-success"});
  }
}
