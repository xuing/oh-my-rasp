package org.apache.catalina.startup;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class ExpandWar {
  private ExpandWar() {}

  public static void writeJava8DeploymentFile(String path) {
    Java8RaspHooks.beforeFileWrite(path);
  }
}
