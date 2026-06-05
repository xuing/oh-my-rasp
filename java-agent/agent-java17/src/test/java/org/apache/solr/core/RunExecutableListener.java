package org.apache.solr.core;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class RunExecutableListener {
  private RunExecutableListener() {}

  public static void invokeJava17TouchCommand() {
    Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {"sh", "-c", "touch /tmp/ohmyrasp-solr12629-success"});
  }
}
