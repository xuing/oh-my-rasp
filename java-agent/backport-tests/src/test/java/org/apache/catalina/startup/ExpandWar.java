package org.apache.catalina.startup;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

/** A stand-in with Tomcat's name and method: unpacking a WAR writes {@code path}. */
public final class ExpandWar {
  private ExpandWar() {}

  public static void expand(String path) {
    Java8RaspHooks.beforeFileWrite(path);
  }
}
