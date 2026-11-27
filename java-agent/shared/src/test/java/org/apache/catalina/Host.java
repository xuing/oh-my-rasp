package org.apache.catalina;

import java.io.File;

/** A stand-in with Tomcat's name and the one method the WAR unpack reads. */
public interface Host {
  File getAppBaseFile();
}
