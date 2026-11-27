package org.apache.catalina.startup;

/** A stand-in with Tomcat's name and method: unpacking a WAR runs {@code write}. */
public final class ExpandWar {
  private ExpandWar() {}

  public static void expand(Runnable write) {
    write.run();
  }

  public static void copy(Runnable write) {
    write.run();
  }
}
