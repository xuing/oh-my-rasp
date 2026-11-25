import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/** All network responses are plain report text, including responses for a class name. */
public final class ClassDefinitionCheck {
  private static final byte[] REPORT = "weekly report".getBytes(StandardCharsets.US_ASCII);
  private static final class Loader extends URLClassLoader {
    Loader(URL url) { super(new URL[] {url}, ClassDefinitionCheck.class.getClassLoader()); }
    void add(URL url) { addURL(url); }
  }

  private static byte[] reportArchive() throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (JarOutputStream jar = new JarOutputStream(bytes)) {
      for (String name : new String[]{"weekly.txt", "fixture/reports/Archived.class"}) {
        jar.putNextEntry(new JarEntry(name));
        jar.write(REPORT);
        jar.closeEntry();
      }
    }
    return bytes.toByteArray();
  }

  private static void checkDefinition(Loader loader, String name, boolean deny) throws Exception {
    boolean blocked = false;
    try {
      loader.loadClass(name);
      throw new AssertionError("report text defined a class");
    } catch (ClassFormatError expected) {
      // The VM received the fixed report text.
    } catch (RuntimeException e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      blocked = true;
    }
    if (blocked != deny) throw new AssertionError("wrong definition decision for " + name);
  }

  static void check(String track, String mode) throws Exception {
    AtomicInteger reads = new AtomicInteger();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    byte[] archive = reportArchive();
    server.createContext("/", exchange -> {
      reads.incrementAndGet();
      byte[] body = exchange.getRequestURI().getPath().endsWith(".jar") ? archive : REPORT;
      if ("HEAD".equals(exchange.getRequestMethod())) {
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
        return;
      }
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
      exchange.close();
    });
    server.start();
    try {
      URL origin = new URL("http://127.0.0.1:" + server.getAddress().getPort() + "/reports/");
      try (Loader loader = new Loader(origin)) {
        loader.add(origin);
        if (loader.loadClass("java.lang.String") != String.class || reads.get() != 0)
          throw new AssertionError("local class resolution changed");
        try (InputStream in = loader.getResourceAsStream("weekly.txt")) {
          if (in == null || in.read() != REPORT[0]) throw new AssertionError("report was unavailable");
        }
        checkDefinition(loader, "fixture.reports.Weekly", "block".equals(mode));
      }
      try (Loader loader = new Loader(new URL(origin, "/report.jar"))) {
        try (InputStream in = loader.getResourceAsStream("weekly.txt")) {
          if (in == null || in.read() != REPORT[0]) throw new AssertionError("archive report unavailable");
        }
        int cached = reads.get();
        checkDefinition(loader, "fixture.reports.Archived", "block".equals(mode));
        if (reads.get() != cached) throw new AssertionError("archive was fetched again for class lookup");
      }
      try (URLClassLoader child = new URLClassLoader(
          new URL[]{ClassDefinitionCheck.class.getProtectionDomain().getCodeSource().getLocation()}, null)) {
        if (child.loadClass("LocalReportMarker").getClassLoader() != child) throw new AssertionError("wrong local class");
      }
      // A virtual classpath supplies bytes locally under an HTTP-looking identifier.
      URL virtual = new URL(null, "http://reports.invalid/virtual/", new URLStreamHandler() {
        @Override protected URLConnection openConnection(URL url) {
          return new URLConnection(url) {
            public void connect() { }
            public InputStream getInputStream() { return new ByteArrayInputStream(REPORT); }
          };
        }
      });
      try (Loader loader = new Loader(virtual)) {
        checkDefinition(loader, "fixture.reports.Virtual", false);
      }
      URL delegated = new URL(null, "report:/weekly/", new URLStreamHandler() {
        @Override protected URLConnection openConnection(URL url) throws java.io.IOException {
          return new URL(origin, "weekly.txt").openConnection();
        }
      });
      try (Loader loader = new Loader(delegated)) {
        checkDefinition(loader, "fixture.reports.Delegated", "block".equals(mode));
      }
      URL member = new URL("jar:" + new URL(origin, "/selected.jar") + "!/weekly.txt");
      try (HttpTransportCheck.Scope selected = new HttpTransportCheck.Scope(track, member.toString())) {
        URLConnection configured = member.openConnection();
        boolean blocked = false;
        try (InputStream in = configured.getInputStream()) {
          if (in.read() != REPORT[0]) throw new AssertionError("selected archive report unavailable");
        } catch (RuntimeException e) {
          if (!HttpTransportCheck.blocked(e)) throw e;
          blocked = true;
        }
        if (blocked != "block".equals(mode)) throw new AssertionError("wrong archive HTTP decision");
      }
    } finally {
      server.stop(0);
    }
  }
}

final class LocalReportMarker {}
