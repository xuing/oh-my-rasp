import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class HttpExchangeCheck {
  public static void main(String[] args) throws Exception {
    boolean monitor = args[1].equals("monitor");
    ExecutorService workers = Executors.newCachedThreadPool();
    CountDownLatch go = new CountDownLatch(1);
    try (HttpTransportCheck.Fixture fixture = new HttpTransportCheck.Fixture()) {
      HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
          .followRedirects(HttpClient.Redirect.NORMAL).proxy(ProxySelector.of(fixture.server.getAddress()))
          .executor(task -> workers.execute(() -> {
            try { go.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            task.run();
          })).build();
      HttpRequest request = HttpRequest.newBuilder(URI.create("http://reports.example.invalid/next?from=fixture-private-ticket"))
          .timeout(Duration.ofSeconds(8)).build();
      CompletableFuture<HttpResponse<String>> selected;
      CompletableFuture<HttpResponse<String>> fixed;
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], request.uri().toString())) {
        selected = client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
      }
      try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope(args[0], "weekly")) {
        fixed = client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
      }
      go.countDown();
      if (!"weekly".equals(fixed.get(10, TimeUnit.SECONDS).body())) throw new AssertionError("fixed receipt");
      boolean denied = false;
      try {
        if (!"weekly".equals(selected.get(10, TimeUnit.SECONDS).body())) throw new AssertionError("selected receipt");
      } catch (Exception e) {
        if (!HttpTransportCheck.blocked(e)) throw e;
        denied = true;
      }
      if (denied == monitor || fixture.redirects.get() != 2 || fixture.receipts.get() != (monitor ? 2 : 1)) {
        throw new AssertionError("submission context or redirect receipt");
      }
    } finally {
      go.countDown();
      workers.shutdownNow();
    }
  }
}
