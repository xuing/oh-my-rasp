package org.apache.catalina.loader;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * A stand-in with the name of Tomcat's web application loader. It defines the stand-in Tomcat startup classes itself
 * (child first), as a web application that ships classes of those names would.
 */
public class WebappClassLoaderBase extends URLClassLoader {
  public WebappClassLoaderBase(URL[] urls, ClassLoader parent) {
    super(urls, parent);
  }

  @Override
  protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
    if (!name.startsWith("org.apache.catalina.startup.")) {
      return super.loadClass(name, resolve);
    }
    synchronized (getClassLoadingLock(name)) {
      Class<?> loaded = findLoadedClass(name);
      return loaded != null ? loaded : findClass(name);
    }
  }
}
