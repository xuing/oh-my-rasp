package org.apache.catalina.startup;

import java.net.URL;
import org.apache.catalina.Host;

/** A stand-in with Tomcat's name: the container class that calls the unpack (Tomcat's fixDocBase). */
public final class ContextConfig {
  private ContextConfig() {}

  public static String fixDocBase(Host host, URL war, String pathname) {
    return ExpandWar.expand(host, war, pathname);
  }
}
