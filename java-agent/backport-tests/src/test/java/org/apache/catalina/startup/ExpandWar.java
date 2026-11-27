package org.apache.catalina.startup;

import io.ohmyrasp.agent.java8.Java8RaspHooks;
import java.net.URL;
import org.apache.catalina.Host;

/**
 * A stand-in with Tomcat's name and the descriptor of its WAR unpack. Tomcat writes the WAR's entries under
 * {@code new File(host.getAppBaseFile(), pathname)}; this one writes the file {@code war} names, through the line's
 * file-write hook.
 */
public final class ExpandWar {
  private ExpandWar() {}

  public static String expand(Host host, URL war, String pathname) {
    Java8RaspHooks.beforeFileWrite(war.getPath());
    return war.getPath();
  }
}
