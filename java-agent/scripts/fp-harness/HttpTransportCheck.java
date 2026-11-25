import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.CacheRequest;
import java.net.CacheResponse;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ResponseCache;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** An in-process HTTP origin and proxy. It only serves fixture content on loopback. */
public class HttpTransportCheck {
  public static final class Request {
    private final String endpoint;
    private final String uri;
    Request(String endpoint) { this(endpoint, "/reports"); }
    Request(String endpoint, String uri) { this.endpoint = endpoint; this.uri = uri; }
    public String getMethod() { return "GET"; }
    public String getRequestURI() { return uri; }
    public String getQueryString() { return ""; }
    public Enumeration<String> getHeaderNames() { return Collections.enumeration(Collections.<String>emptyList()); }
    public Map<String, String[]> getParameterMap() { return Collections.singletonMap("endpoint", new String[]{endpoint}); }
  }

  public static final class Scope implements AutoCloseable {
    private final Class<?> hooks;
    private final boolean modern;
    Scope(String track, String endpoint) throws Exception { this(track, endpoint, "/reports"); }
    Scope(String track, String endpoint, String uri) throws Exception {
      modern = track.equals("main");
      hooks = Class.forName(modern ? "io.ohmyrasp.agent.hook.OhMyRaspHooks"
          : "io.ohmyrasp.agent.java" + track + ".Java" + track + "RaspHooks");
      if (modern) hooks.getMethod("enterHttpRequest", Object.class, Object.class).invoke(null, new Request(endpoint, uri), null);
      else hooks.getMethod("beforeHttpRequest", Object.class).invoke(null, new Request(endpoint, uri));
    }
    @Override public void close() throws Exception {
      hooks.getMethod(modern ? "exitHttpRequest" : "afterHttpRequest").invoke(null);
    }
  }

  static final class Fixture implements AutoCloseable {
    final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final AtomicInteger receipts = new AtomicInteger();
    final AtomicInteger redirects = new AtomicInteger();
    final String root = "http://127.0.0.1:" + server.getAddress().getPort();
    final String destination = root + "/report?ticket=fixture-private-ticket";
    Fixture() throws Exception {
      server.createContext("/", exchange -> {
        if (exchange.getRequestURI().getPath().equals("/next")) {
          redirects.incrementAndGet();
          exchange.getResponseHeaders().set("Location", destination);
          exchange.sendResponseHeaders(302, -1);
        } else {
          receipts.incrementAndGet();
          byte[] bytes = "weekly".getBytes(StandardCharsets.US_ASCII);
          exchange.sendResponseHeaders(200, bytes.length);
          exchange.getResponseBody().write(bytes);
        }
        exchange.close();
      });
      server.start();
    }
    Proxy proxy() { return new Proxy(Proxy.Type.HTTP, server.getAddress()); }
    @Override public void close() { server.stop(0); }
  }

  static boolean blocked(Throwable error) {
    for (Throwable t = error; t != null; t = t.getCause()) {
      if (t.getClass().getSimpleName().endsWith("RaspBlockException")) return true;
    }
    return false;
  }

  static String read(URLConnection connection) throws Exception {
    connection.setConnectTimeout(2500);
    connection.setReadTimeout(2500);
    try (InputStream in = connection.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[128];
      for (int n; (n = in.read(buffer)) != -1;) out.write(buffer, 0, n);
      return out.toString("UTF-8");
    }
  }

  private static ResponseCache cache() {
    return new ResponseCache() {
      public CacheResponse get(URI uri, String method, Map<String,List<String>> headers) {
        return new CacheResponse() {
          public Map<String,List<String>> getHeaders() {
            Map<String,List<String>> result = new HashMap<>();
            result.put(null, Collections.singletonList("HTTP/1.1 200 OK"));
            return result;
          }
          public InputStream getBody() { return new ByteArrayInputStream(new byte[]{65}); }
        };
      }
      public CacheRequest put(URI uri, URLConnection connection) { return null; }
    };
  }

  public static void main(String[] args) throws Exception {
    boolean monitor = args[1].equals("monitor");
    try (Fixture fixture = new Fixture()) {
      URL target = new URL(fixture.destination);
      try (Scope scope = new Scope(args[0], fixture.destination)) {
        HttpURLConnection unused = (HttpURLConnection) target.openConnection(Proxy.NO_PROXY);
        unused.setRequestProperty("X-Report", "weekly");
        unused.disconnect();
        ResponseCache original = ResponseCache.getDefault();
        try {
          ResponseCache.setDefault(cache());
          if (!read(target.openConnection(Proxy.NO_PROXY)).equals("A")) throw new AssertionError("cache body");
        } finally { ResponseCache.setDefault(original); }
      }
      if (fixture.receipts.get() != 0) throw new AssertionError("unexpected network activity");
      // Proxy explicitly points to this fixture. No lookup or forwarding to this hostname is needed.
      URL origin = new URL("http://reports.example.invalid/next?from=fixture-private-ticket");
      boolean denied = false;
      try (Scope scope = new Scope(args[0], origin.toString())) {
        try {
          if (!read(origin.openConnection(fixture.proxy())).equals("weekly")) throw new AssertionError("report body");
        } catch (Exception e) {
          if (!blocked(e)) throw e;
          denied = true;
        }
      }
      if (denied == monitor || fixture.redirects.get() != 1 || fixture.receipts.get() != (monitor ? 1 : 0)) {
        throw new AssertionError("redirect decision or receiver count");
      }
      String resolver = "http://169.254.169.253/weekly-fixture";
      String printer = "http://[fe80::a%25FloorA]/weekly-fixture";
      checkProxyRead(fixture, args[0], "weekly", resolver, false);
      checkProxyRead(fixture, args[0], resolver, resolver, !monitor);
      checkProxyRead(fixture, args[0], printer.replace("FloorA", "floora"), printer, false);
      checkProxyRead(fixture, args[0], printer.replace("fe80::a", "FE80:0:0:0:0:0:0:A"), printer, !monitor);
      checkProxyRead(fixture, args[0], "weekly", "http://169.254.169.254/weekly-fixture", !monitor);
    }
  }

  // The explicit proxy serves the fixed fixture response and never forwards the logical target.
  private static void checkProxyRead(Fixture fixture, String track, String supplied, String target,
      boolean expectBlock) throws Exception {
    int before = fixture.receipts.get();
    boolean denied = false;
    try (Scope scope = new Scope(track, supplied)) {
      HttpURLConnection connection = (HttpURLConnection) new URL(target).openConnection(fixture.proxy());
      connection.setInstanceFollowRedirects(false);
      try {
        if (!read(connection).equals("weekly")) throw new AssertionError("proxy response body");
      } catch (Exception e) {
        if (!blocked(e)) throw e;
        denied = true;
      }
    }
    if (denied != expectBlock || fixture.receipts.get() != before + (expectBlock ? 0 : 1)) {
      throw new AssertionError("proxy decision or receiver count for " + target);
    }
  }
}
