package org.apache.catalina.startup;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class ExpandWar {
  private ExpandWar() {}

  public static void writeJava11DeploymentFile(String path) {
    Java11RaspHooks.beforeFileWrite(path);
  }
}
