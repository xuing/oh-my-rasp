import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.server.RMIClassLoader;
import java.lang.reflect.Proxy;

/** Verify local resolution and annotation handling without downloading or defining any remote class. */
public class RmiCodebaseCheck {
  public static void main(String[] args) throws Exception {
    String annotation = "https://reports.invalid/catalog/";
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "weekly")) {
      ClassLoader local = RmiCodebaseCheck.class.getClassLoader();
      if (RMIClassLoader.loadClass(annotation, RmiCodebaseCheck.class.getName(), local) != RmiCodebaseCheck.class)
        throw new AssertionError("wrong local class");
      if (RMIClassLoader.loadClass(new URL(annotation), "java.lang.String") != String.class)
        throw new AssertionError("wrong bootstrap class");
      if (!Proxy.isProxyClass(RMIClassLoader.loadProxyClass(annotation, new String[]{"java.lang.Runnable"}, local)))
        throw new AssertionError("wrong local proxy");
      if (RMIClassLoader.getClassLoader(annotation) != Thread.currentThread().getContextClassLoader())
        throw new AssertionError("wrong context loader");
      try {
        RMIClassLoader.loadClass(annotation + " invalid-url", "java.lang.String", local);
        throw new AssertionError("invalid annotation accepted");
      } catch (MalformedURLException expected) { }
      int[] displayCalls = {0};
      URL localUrl = new URL(null, "file:/weekly https://reports.invalid/catalog/", new java.net.URLStreamHandler() {
        @Override protected java.net.URLConnection openConnection(URL value) { throw new AssertionError("opened local URL"); }
        @Override protected String toExternalForm(URL value) { displayCalls[0]++; return "https://reports.invalid/catalog/"; }
      });
      try (URLClassLoader localLoader = new URLClassLoader(new URL[]{localUrl}, local)) {
        if (localLoader.loadClass("java.lang.String") != String.class) throw new AssertionError("wrong parent class");
      }
      if (displayCalls[0] != 0) throw new AssertionError("agent formatted a local classpath element");
      // This separate operation actually gives a URL to a codebase loader. Never use it to load code.
      boolean blocked = false;
      try (URLClassLoader loader = new URLClassLoader(new URL[]{new URL(annotation)}, local)) {
        if (loader.getURLs().length != 1) throw new AssertionError("lost classpath");
      } catch (RuntimeException e) {
        if (!HttpTransportCheck.blocked(e)) throw e;
        blocked = true;
      }
      if (blocked != "block".equals(args[1])) throw new AssertionError("wrong classpath policy decision");
    }
  }
}
