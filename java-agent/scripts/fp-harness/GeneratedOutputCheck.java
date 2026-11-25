import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Write-only probes. No generated text is executed. */
public class GeneratedOutputCheck {
  public static void main(String[] args) throws Exception {
    int rounds = args.length > 1 ? Integer.parseInt(args[1]) : 1;
    String mode = args[0];
    Path dir = Files.createTempDirectory("generated-output");
    Path file = dir.resolve("document.tmp");
    String operation = "system(\"printf weekly\")";
    try {
      for (int round = 0; round < rounds; round++) {
        for (int i = 0; i < 5; i++) {
          int k = (round + i) % 5;
          String input = k == 0 ? "Runtime.exec(String)" : k == 1 ? "weekly" : k == 4 ? "printf weekly" : operation;
          String content;
          switch (k) {
            case 0: content = "{\"label\":\"Runtime.exec(String)\",\"status\":\"ok\"}\n"; break;
            case 1: content = "{\"label\":\"Runtime.exec(String)\",\"report\":\"weekly\"}\n"; break;
            case 2: content = "# reference: " + operation + "\n"; break;
            default: content = "value = " + operation + "\n";
          }
          Files.writeString(file, "previous");
          boolean denied = false;
          try (HttpTransportCheck.Scope ignored = new HttpTransportCheck.Scope("main", input)) {
            // Choose the charset overload to reach one content handoff.
            Files.writeString(file, content, java.nio.charset.StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
          } catch (Exception failure) {
            if (!HttpTransportCheck.blocked(failure)) throw failure;
            denied = true;
          }
          if (!Files.readString(file).equals(denied ? "previous" : content))
            throw new AssertionError("on-disk content did not match the decision");
          System.out.println("row," + k + "," + denied);
          if (!mode.equals("observe") && denied != (k >= 3 && mode.equals("block"))) throw new AssertionError("data vs program");
        }
      }
    } finally {
      Files.deleteIfExists(file);
      Files.delete(dir);
    }
  }
}
