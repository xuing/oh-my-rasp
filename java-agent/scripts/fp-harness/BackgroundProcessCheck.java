import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** A background application job with a fixed shell pipeline and ordinary positional data. */
public final class BackgroundProcessCheck {
  public static void main(String[] args) throws Exception {
    ExecutorService worker = Executors.newSingleThreadExecutor();
    try {
      for (String value : new String[]{"O'Brien", "R&D", "June|July", "Q1;Q2"}) {
        String actual = worker.submit(() -> format(value)).get();
        if (!value.equals(actual)) {
          throw new AssertionError("Background job returned unexpected output");
        }
      }
    } finally {
      worker.shutdownNow();
    }
  }

  private static String format(String value) throws Exception {
    Process child = new ProcessBuilder("sh", "-c", "printf '%s\\n' \"$1\" | cat", "formatter", value).start();
    try (BufferedReader output = new BufferedReader(
        new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8))) {
      String line = output.readLine();
      if (output.readLine() != null || child.waitFor() != 0) {
        throw new AssertionError("Background job failed");
      }
      return line;
    }
  }
}
