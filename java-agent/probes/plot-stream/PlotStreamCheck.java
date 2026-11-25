import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.FutureTask;

/** These are inert file-write fixtures. No plot interpreter is started. */
public class PlotStreamCheck {
  private static final byte[] directive = "set yrange [0:system(0)]\n".getBytes(StandardCharsets.UTF_8);
  private static boolean append(FileOutputStream out, byte[] bytes) throws Exception {
    try { out.write(bytes); return true; }
    catch (RuntimeException ex) {
      if (!HttpTransportCheck.blocked(ex)) throw ex;
      return false;
    }
  }
  public static void main(String[] args) throws Exception {
    boolean block = args[0].equals("block"), observe = args[0].equals("observe");
    Path work = Files.createTempDirectory("plot-receipts");
    Path notes = work.resolve("guide.txt"), plot = work.resolve("chart.plot");
    boolean notesWritten, chartWritten;
    try {
      try (FileOutputStream text = new FileOutputStream(notes.toFile());
           FileOutputStream chart = new FileOutputStream(plot.toFile())) {
        boolean written = append(text, directive);
        notesWritten = written;
        if (!observe && (!written || !Arrays.equals(Files.readAllBytes(notes), directive)))
          throw new AssertionError("write was attributed to another stream");
      }
      try (FileOutputStream chart = new FileOutputStream(plot.toFile());
           FileOutputStream text = new FileOutputStream(notes.toFile(), true)) {
        FutureTask<Boolean> worker = new FutureTask<>(() -> append(chart, directive));
        Thread thread = new Thread(worker);
        thread.start();
        boolean written = worker.get();
        thread.join();
        chartWritten = written;
        if (!observe && (written == block || !Arrays.equals(Files.readAllBytes(plot), block ? new byte[0] : directive)))
          throw new AssertionError("lost stream identity at handoff");
      }
      if (!observe) {
        try (FileOutputStream chart = new FileOutputStream(plot.toFile())) {
          byte[] title = "set key title 'system(0)' # set xrange [system(0)]\n".getBytes(StandardCharsets.UTF_8);
          chart.write(title);
          try {
            chart.write(directive, 0, directive.length + 1);
            throw new AssertionError("invalid slice accepted");
          } catch (IndexOutOfBoundsException expected) { }
          if (!Arrays.equals(Files.readAllBytes(plot), title)) throw new AssertionError("title changed");
          byte[] prefix = "set xrange [system".getBytes(StandardCharsets.UTF_8);
          chart.write(prefix);
          boolean denied = false;
          try { chart.write('('); }
          catch (RuntimeException e) { if (!HttpTransportCheck.blocked(e)) throw e; denied = true; }
          if (denied != block) throw new AssertionError("single-byte completion");
          if (Files.size(plot) != title.length + prefix.length + (denied ? 0 : 1)) throw new AssertionError("partial write");
        }
      }
      System.out.println("notes," + notesWritten);
      System.out.println("cross-thread," + chartWritten);
    } finally { Files.deleteIfExists(plot); Files.deleteIfExists(notes); Files.delete(work); }
  }
}
