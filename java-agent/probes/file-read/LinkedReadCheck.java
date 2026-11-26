import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/** Linux fixture. Protected-target controls open and close a descriptor without reading its contents. */
public class LinkedReadCheck {
  interface Read { void run() throws Exception; }

  private static void check(String track, String mode, String label, String source, boolean policy, Read read) throws Exception {
    boolean blocked = false;
    try (HttpTransportCheck.Scope ignored = track.equals("off") ? null : new HttpTransportCheck.Scope(track, source)) {
      read.run();
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      blocked = true;
    }
    System.out.println("row," + label + "," + policy + "," + blocked);
    if (!mode.equals("observe") && blocked != (mode.equals("block") && policy)) throw new AssertionError(label);
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path root = Files.createTempDirectory("linked-report");
    Path hosts = Paths.get("/etc/hosts");
    Path link = Files.createSymbolicLink(root.resolve("report.txt"), hosts);
    Path directory = Files.createSymbolicLink(root.resolve("config"), hosts.getParent());
    Path reported = directory.resolve(hosts.getFileName());
    Path ordinary = Files.write(root.resolve("weekly.csv"), new byte[]{42});
    Path document = Files.createSymbolicLink(root.resolve("summary.json"), ordinary.getFileName());
    Path missing = Files.createSymbolicLink(root.resolve("absent.txt"), root.resolve("missing"));
    Path deployment = Files.createDirectory(root.resolve("WEB-INF"));
    Path template = Files.write(deployment.resolve("weekly.txt"), new byte[]{42});
    Path preview = Files.createSymbolicLink(root.resolve("preview.txt"), template);
    try {
      for (int r = 0; r < rounds; r++) {
        check(track, mode, "regular-csv", ordinary.toString(), false, () -> {
          if (Files.readAllBytes(ordinary)[0] != 42) throw new AssertionError();
        });
        check(track, mode, "linked-json", document.toString(), false, () -> {
          if (Files.readAllBytes(document)[0] != 42) throw new AssertionError();
        });
        check(track, mode, "fixed-link", "weekly", false, () -> {
          try (FileChannel ignored = FileChannel.open(link)) { }
        });
        check(track, mode, "selected-channel", link.toString(), true, () -> {
          try (FileChannel ignored = FileChannel.open(link)) { }
        });
        check(track, mode, "selected-stream", link.toString(), true, () -> {
          try (FileInputStream ignored = new FileInputStream(link.toString())) { }
        });
        check(track, mode, "selected-random-access", link.toString(), true, () -> {
          try (RandomAccessFile ignored = new RandomAccessFile(link.toFile(), "r")) { }
        });
        check(track, mode, "parent-link", reported.toString(), true, () -> {
          try (FileChannel ignored = FileChannel.open(reported, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) { }
        });
        check(track, mode, "no-follow", link.toString(), false, () -> {
          try (FileChannel ignored = FileChannel.open(link, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            throw new AssertionError("opened a final symlink");
          } catch (IOException expected) {
            if (HttpTransportCheck.blocked(expected)) throw expected;
          }
        });
        check(track, mode, "deployment-file", preview.toString(), track.equals("main"), () -> {
          if (Files.readAllBytes(preview)[0] != 42) throw new AssertionError();
        });
        check(track, mode, "missing-target", missing.toString(), false, () -> {
          try (FileChannel ignored = FileChannel.open(missing)) { throw new AssertionError("opened missing target"); }
          catch (NoSuchFileException expected) { }
        });
      }
    } finally {
      for (Path p : new Path[]{preview, template, deployment, missing, document, ordinary, directory, link, root}) Files.delete(p);
    }
  }
}
