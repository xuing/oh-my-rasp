package org.apache.catalina.startup;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class ExpandWar {
  private ExpandWar() {}

  public static void writeJava17DeploymentFile(String path) {
    Java17RaspHooks.beforeFileWrite(path);
  }
}
