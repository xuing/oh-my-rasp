package org.apache.catalina.core;

import java.io.File;
import org.apache.catalina.Host;

/** A stand-in with Tomcat's name: a Host whose appBase is the directory it was given. */
public final class StandardHost implements Host {
  private final File appBase;

  public StandardHost(File appBase) {
    this.appBase = appBase;
  }

  @Override public File getAppBaseFile() {
    return appBase;
  }
}
