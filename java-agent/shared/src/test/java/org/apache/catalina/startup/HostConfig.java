package org.apache.catalina.startup;

/** A stand-in with Tomcat's name: the deployer that unpacks a WAR. */
public final class HostConfig {
  private HostConfig() {}

  public static void deployWAR(Runnable write) {
    ExpandWar.expand(write);
  }

  public static void copyWAR(Runnable write) {
    ExpandWar.copy(write);
  }
}
