package org.apache.catalina.startup;

import io.ohmyrasp.agent.file.DeploymentWork;
import java.net.URL;
import org.apache.catalina.Host;

/**
 * A stand-in with Tomcat's name and the descriptor of its WAR unpack. Tomcat writes the WAR's entries under
 * {@code new File(host.getAppBaseFile(), pathname)}; this one writes the file {@code war} names.
 */
public final class ExpandWar {
  private ExpandWar() {}

  public static String expand(Host host, URL war, String pathname) throws Exception {
    return DeploymentWork.inside(war.getPath());
  }

  public static String copy(Host host, URL war, String pathname) throws Exception {
    return DeploymentWork.inside(war.getPath());
  }
}
