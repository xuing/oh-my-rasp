package io.ohmyrasp.agent.net;

import io.ohmyrasp.agent.util.WeakOwners;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.concurrent.CompletableFuture;

/** Correlates a logged acquisition with the first write of that same URL on the same connection. */
public final class HttpTransportObservation {
  private static final WeakOwners<Mark> PENDING = new WeakOwners<Mark>();

  // Submission evidence follows the JDK exchange across executor threads and redirects.
  // Values must not contain a reference to the exchange or to a live servlet request.
  public static final class Submissions<T> {
    private final WeakOwners<T> origins = new WeakOwners<T>();
    public void capture(Object exchange, T context) {
      if (context != null) origins.put(exchange, context);
    }
    public T origin(Object exchange) { return origins.get(exchange); }
    public void finishedWhen(CompletableFuture<?> future, final Object exchange) {
      if (future != null && origins.get(exchange) != null) {
        future.whenComplete((result, failure) -> origins.remove(exchange));
      }
    }
  }

  private static final WeakOwners<WeakReference<URL>> REDIRECTS = new WeakOwners<WeakReference<URL>>();
  private static final WeakOwners<WeakReference<URI>> SUBMITTED_TARGETS = new WeakOwners<WeakReference<URI>>();

  private static final ThreadLocal<Acquisition> ACQUIRING = new ThreadLocal<Acquisition>();

  private static final class Acquisition {
    final Acquisition parent;
    final URL redirectedTarget;
    Acquisition(Acquisition parent, URL target) {
      this.parent = parent;
      redirectedTarget = target;
    }
  }

  public static void enterAcquisition(Object connection) {
    Acquisition parent = ACQUIRING.get();
    WeakReference<URL> target = REDIRECTS.get(connection);
    if (parent != null || target != null) ACQUIRING.set(new Acquisition(parent, target == null ? null : target.get()));
  }

  public static void exitAcquisition() {
    Acquisition current = ACQUIRING.get();
    if (current == null) return;
    if (current.parent == null) ACQUIRING.remove();
    else ACQUIRING.set(current.parent);
  }

  public static boolean dialingRedirect(URL url) {
    Acquisition current = ACQUIRING.get();
    return current != null && current.redirectedTarget == url;
  }

  public static void selectedRedirect(Object connection, URL from, URL to, boolean supplied) {
    if (supplied || redirected(connection, from)) REDIRECTS.put(connection, new WeakReference<URL>(to));
    else REDIRECTS.remove(connection);
  }

  public static boolean redirected(Object connection, URL to) {
    WeakReference<URL> ref = REDIRECTS.get(connection);
    return ref != null && ref.get() == to;
  }

  public static void selectedSubmission(Object multi, URI uri) {
    SUBMITTED_TARGETS.put(multi, new WeakReference<URI>(uri));
  }

  public static boolean changedOrigin(Object multi, URI uri) {
    WeakReference<URI> ref = SUBMITTED_TARGETS.get(multi);
    URI first = ref == null ? null : ref.get();
    return first != null && (!NetworkHost.destinationKey(first.getHost()).equals(NetworkHost.destinationKey(uri.getHost()))
        || httpPort(first.getScheme(), first.getPort()) != httpPort(uri.getScheme(), uri.getPort())
        || !first.getScheme().equalsIgnoreCase(uri.getScheme()));
  }

  private static final WeakOwners<Route> ROUTES = new WeakOwners<Route>();
  private static final WeakOwners<WeakReference<Object>> EXCHANGES = new WeakOwners<WeakReference<Object>>();

  private static final class Route {
    final WeakReference<URL> url;
    final String host;
    final int port;
    volatile String peer;
    Route(URL url) {
      this.url = new WeakReference<URL>(url);
      host = NetworkHost.destinationKey(url.getHost());
      port = httpPort(url.getProtocol(), url.getPort());
    }
  }

  private static int httpPort(String scheme, int port) {
    return port < 0 ? ("https".equalsIgnoreCase(scheme) ? 443 : 80) : port;
  }

  public static void beginRoute(Object client, URL url, Proxy proxy) {
    String host = url == null ? "" : NetworkHost.normalize(url.getHost());
    if (isHttp(url) && (proxy == null || proxy == Proxy.NO_PROXY)
        && !NetworkHost.isInternal(host) && !NetworkHost.isMetadata(host)) {
      ROUTES.put(client, new Route(url));
    } else {
      ROUTES.remove(client);
    }
  }

  public static URL dialTarget(Object client, SocketAddress address) {
    Route route = ROUTES.get(client);
    if (route == null || !(address instanceof InetSocketAddress)) return null;
    route.peer = internalAddress((InetSocketAddress) address, route.host, route.port);
    return route.peer == null ? null : route.url.get();
  }

  public static String peer(Object client, URL target) {
    Route route = ROUTES.get(client);
    if (route == null || target == null || route.port != httpPort(target.getProtocol(), target.getPort())
        || !route.host.equals(NetworkHost.destinationKey(target.getHost()))) return null;
    return route.peer;
  }

  public static void bindExchange(Object request, Object multi, URI uri) {
    String host = NetworkHost.normalize(uri.getHost());
    if (!NetworkHost.isInternal(host) && !NetworkHost.isMetadata(host)) {
      EXCHANGES.put(request, new WeakReference<Object>(multi));
    }
  }

  public static Object submittedExchange(Object request) {
    WeakReference<Object> ref = EXCHANGES.get(request);
    return ref == null ? null : ref.get();
  }

  public static String directAddress(URI target, InetSocketAddress address, InetSocketAddress proxy) {
    if (target == null || proxy != null) return null;
    String host = NetworkHost.normalize(target.getHost());
    if (NetworkHost.isInternal(host) || NetworkHost.isMetadata(host)) return null;
    return internalAddress(address, NetworkHost.destinationKey(host), httpPort(target.getScheme(), target.getPort()));
  }

  private static String internalAddress(InetSocketAddress address, String host, int port) {
    if (address == null || address.getAddress() == null || port != address.getPort()
        || !host.equals(NetworkHost.destinationKey(address.getHostString()))) return null;
    // Read the JDK's resolution result. No DNS lookup or reverse lookup is performed here.
    InetAddress ip = address.getAddress();
    return NetworkHost.isInternal(ip) || NetworkHost.isMetadata(ip) ? ip.getHostAddress() : null;
  }

  private HttpTransportObservation() {}

  public static boolean isHttp(URL url) {
    return url != null && ("http".equalsIgnoreCase(url.getProtocol()) || "https".equalsIgnoreCase(url.getProtocol()));
  }

  /** HTTP request targets exclude user-info and fragments. URL.toExternalForm calls application handler code. */
  public static String address(URL url) {
    return address(url.getProtocol(), url.getHost(), url.getPort(), url.getPath(), url.getQuery());
  }

  public static String address(URI uri) {
    return address(uri.getScheme(), uri.getHost(), uri.getPort(), uri.getRawPath(), uri.getRawQuery());
  }

  private static String address(String scheme, String host, int port, String path, String query) {
    return scheme + "://" + (host == null ? "" : host) + (port < 0 ? "" : ":" + port)
        + (path == null || path.isEmpty() ? "/" : path) + (query == null ? "" : "?" + query);
  }

  public static String recordedAddress(String address) {
    int end = address.indexOf('?');
    return end < 0 ? address : address.substring(0, end);
  }

  public static URI comparisonUri(URL url, String address) {
    try {
      return new URI(address);
    } catch (URISyntaxException nonUriPath) {
      try {
        return new URI(url.getProtocol(), null, url.getHost(), url.getPort(), url.getPath(), url.getQuery(), null);
      } catch (URISyntaxException unavailable) {
        return null;
      }
    }
  }

  public static boolean repeated(Object connection, URL url, Object request, String algorithm, boolean write) {
    if (write) {
      Mark prior = PENDING.remove(connection);
      return prior != null && prior.url.get() == url && prior.context.get() == request
          && prior.hadRequest == (request != null) && prior.algorithm.equals(algorithm);
    }
    PENDING.put(connection, new Mark(url, request, algorithm));
    return false;
  }

  private static final class Mark {
    final WeakReference<URL> url;
    final WeakReference<Object> context;
    final boolean hadRequest;
    final String algorithm;
    Mark(URL url, Object context, String algorithm) {
      this.url = new WeakReference<URL>(url);
      this.context = new WeakReference<Object>(context);
      this.hadRequest = context != null;
      this.algorithm = algorithm;
    }
  }
}
