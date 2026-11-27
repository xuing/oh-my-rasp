package org.apache.catalina.startup;

/** A stand-in with Tomcat's name: the deployer that unpacks a WAR. */
public final class HostConfig {
  private HostConfig() {}

  public static void deployJava8War(String path) {
    ExpandWar.expand(path);
  }
}
