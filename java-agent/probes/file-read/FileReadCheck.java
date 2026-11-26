import java.io.InputStream;
import java.net.URI;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** All reports contain fixture bytes. Reads of the system hosts file only open the descriptor. */
public class FileReadCheck {
  interface Operation { void run() throws Exception; }

  private static void check(String track, String mode, String name, String source,
      boolean policy, Operation op) throws Exception {
    boolean denied = false;
    try (HttpTransportCheck.Scope scope = track.equals("off") ? null : new HttpTransportCheck.Scope(track, source)) {
      op.run();
    } catch (Exception e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      denied = true;
    }
    System.out.println("row," + name + "," + policy + "," + denied);
    if (!mode.equals("observe") && denied != (policy && mode.equals("block"))) {
      throw new AssertionError("unexpected read decision for " + name);
    }
  }

  private static void checkBody(Path path) throws Exception {
    byte[] bytes = Files.readAllBytes(path);
    if (bytes.length != 1 || bytes[0] != 42) throw new AssertionError("report content");
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path dir = Files.createTempDirectory("file-read-check");
    Path hosts = Paths.get("/etc/hosts");
    Path mirror = dir.resolve("snapshot/etc/passwd");
    Path link = dir.resolve("links/etc/passwd");
    Path zip = dir.resolve("reports.zip");
    Files.createDirectories(mirror.getParent());
    Files.write(mirror, new byte[]{42});
    Files.createDirectories(link.getParent());
    Files.createSymbolicLink(link, mirror);
    try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(zip))) {
      for (String entry : new String[]{"etc/hosts", "etc/passwd", "proc/self/environ"}) {
        out.putNextEntry(new ZipEntry(entry));
        out.write(42);
        out.closeEntry();
      }
    }
    try (FileSystem archive = FileSystems.newFileSystem(URI.create("jar:" + zip.toUri()), Collections.<String,String>emptyMap())) {
      for (int r = 0; r < rounds; r++) {
        String normal = "weekly-" + r;
        check(track, mode, "hosts-fixed", normal, false, () -> {
          try (InputStream in = Files.newInputStream(hosts)) { }
        });
        check(track, mode, "hosts-name-only", "hosts", false, () -> {
          try (FileChannel ch = FileChannel.open(hosts)) { }
        });
        check(track, mode, "space-in-filename", " " + hosts + " ", false, () -> {
          try (FileChannel ch = FileChannel.open(hosts)) { }
        });
        check(track, mode, "literal-backslash", "/etc\\hosts", false, () -> {
          try (FileChannel ch = FileChannel.open(hosts)) { }
        });
        check(track, mode, "attributes", hosts.toString(), false, () -> {
          if (!Files.readAttributes(hosts, BasicFileAttributes.class).isRegularFile()) throw new AssertionError();
        });
        check(track, mode, "symbolic-link-value", normal, false, () -> {
          if (!Files.readSymbolicLink(link).equals(mirror)) throw new AssertionError();
        });
        check(track, mode, "project-snapshot", normal, false, () -> checkBody(mirror));
        for (String entry : new String[]{"/etc/hosts", "/etc/passwd", "/proc/self/environ"}) {
          check(track, mode, "zip-entry" + entry, entry, false, () -> checkBody(archive.getPath(entry)));
        }
        check(track, mode, "byte-channel", hosts.toString(), true, () -> {
          try (SeekableByteChannel ch = Files.newByteChannel(hosts)) { }
        });
        check(track, mode, "file-channel", hosts.toString(), true, () -> {
          try (FileChannel ch = FileChannel.open(hosts, StandardOpenOption.READ)) { }
        });
        check(track, mode, "async-channel", hosts.toString(), true, () -> {
          try (AsynchronousFileChannel ch = AsynchronousFileChannel.open(hosts)) { }
        });
        check(track, mode, "provider", hosts.toString(), true, () -> {
          try (SeekableByteChannel ch = hosts.getFileSystem().provider().newByteChannel(hosts,
              Collections.singleton(StandardOpenOption.READ))) { }
        });
      }
    } finally {
      Files.delete(zip);
      Files.delete(link);
      Files.delete(link.getParent());
      Files.delete(link.getParent().getParent());
      Files.delete(mirror);
      Files.delete(mirror.getParent());
      Files.delete(mirror.getParent().getParent());
      Files.delete(dir);
    }
  }
}
