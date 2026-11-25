import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Iterator;

/** Observe the exact string or line materialized by Files; never run the contents. */
public class RenderedWriteCheck {
  static final class Text implements CharSequence {
    final String value;
    int conversions;
    Text(String value) { this.value = value; }
    public int length() { return value.length(); }
    public char charAt(int i) { return value.charAt(i); }
    public CharSequence subSequence(int a, int b) { return value.subSequence(a, b); }
    @Override public String toString() { conversions++; return value; }
  }

  static final class Lines implements Iterable<CharSequence> {
    final Text line;
    int iterations;
    Lines(Text line) { this.line = line; }
    public Iterator<CharSequence> iterator() {
      if (++iterations > 1) throw new IllegalStateException("iterator was already consumed");
      return Arrays.<CharSequence>asList("header", line, "trailer").iterator();
    }
  }

  public static void main(String[] args) throws Exception {
    int rounds = args.length > 1 ? Integer.parseInt(args[1]) : 1;
    String mode = args[0];
    Path dir = Files.createTempDirectory("rendered-document"), file = dir.resolve("document.tmp");
    String operation = "system(\"printf weekly\")";
    try {
      for (int n = 0; n < rounds; n++) for (int k = 0; k < 4; k++) {
        boolean script = (k % 2 == 1), streamed = k >= 2, denied = false;
        Text text = new Text(script ? "value = " + operation : "{\"reference\":\"Runtime.exec(String)\",\"label\":\"weekly\"}");
        Lines lines = new Lines(text);
        Files.writeString(file, "previous");
        try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", script ? operation : "weekly")) {
          if (streamed) Files.write(file, lines, StandardCharsets.UTF_8);
          else Files.writeString(file, text, StandardCharsets.UTF_16LE);
        } catch (Exception failure) {
          if (!HttpTransportCheck.blocked(failure)) throw failure;
          denied = true;
        }
        if (text.conversions != 1 || lines.iterations != (streamed ? 1 : 0)) throw new AssertionError("extra application callback");
        if (denied != (script && mode.equals("block"))) throw new AssertionError("decision");
        String expected = streamed ? ("header\n" + (denied ? "" : text.value + "\ntrailer\n"))
            : (denied ? "previous" : text.value);
        String actual = Files.readString(file, streamed || denied ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE);
        if (!actual.equals(expected)) throw new AssertionError("file receipt");
        System.out.println("row," + k + "," + denied);
      }
    } finally { Files.deleteIfExists(file); Files.delete(dir); }
  }
}
