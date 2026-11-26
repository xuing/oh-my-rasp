import java.io.File;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Checks ordinary directory contents and whether a filter or iterator was reached. */
public class DirectoryCheck {
  interface Listing { void run() throws Exception; }

  private static boolean check(String track, String mode, String label, String input, boolean protectedTarget, Listing listing) throws Exception {
    boolean denied = false;
    try (HttpTransportCheck.Scope scope = track.equals("off") ? null : new HttpTransportCheck.Scope(track, input)) {
      listing.run();
    } catch (Exception ex) {
      if (!HttpTransportCheck.blocked(ex)) throw ex;
      denied = true;
    }
    System.out.println("row," + label + "," + protectedTarget + "," + denied);
    if (!mode.equals("observe") && denied != (protectedTarget && mode.equals("block"))) throw new AssertionError(label);
    return denied;
  }

  static int descriptorCount(Path directory) throws java.io.IOException {
    int count = 0;
    try (DirectoryStream<Path> fds = Files.newDirectoryStream(Paths.get("/proc/self/fd"))) {
      for (Path fd : fds) {
        try {
          if (Files.isSameFile(fd, directory)) count++;
        } catch (NoSuchFileException closed) {
          // Other JVM activity can close an unrelated descriptor during the snapshot.
        }
      }
    }
    return count;
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path root = Files.createTempDirectory("monthly-reports");
    Path reports = Files.createDirectory(root.resolve("orders"));
    Path page = Files.createFile(reports.resolve("weekly.csv"));
    Path config = Paths.get("/etc");
    Path link = Files.createSymbolicLink(root.resolve("selected"), config);
    Path archive = root.resolve("reports.zip");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      zip.putNextEntry(new ZipEntry("etc/weekly.csv"));
      zip.write(42);
      zip.closeEntry();
    }
    try (FileSystem zip = FileSystems.newFileSystem(URI.create("jar:" + archive.toUri()), Collections.<String,String>emptyMap());
         DirectoryStream<Path> parent = Files.newDirectoryStream(root)) {
      int initialDescriptors = descriptorCount(config);
      for (int n = 0; n < rounds; n++) {
        check(track, mode, "substring", "orders", false, () -> {
          if (!Arrays.equals(reports.toFile().list(), new String[]{"weekly.csv"})) throw new AssertionError();
        });
        check(track, mode, "ordinary-exact", reports.toString(), false, () -> {
          try (Stream<Path> files = Files.list(reports)) {
            if (!files.findFirst().get().equals(page)) throw new AssertionError();
          }
        });
        check(track, mode, "fixed-protected-directory", "weekly", false, () -> {
          if (config.toFile().list() == null) throw new AssertionError("fixture directory is unavailable");
        });
        check(track, mode, "reflected", "weekly", false, () -> {
          String[] names = (String[]) File.class.getMethod("list").invoke(reports.toFile());
          if (names.length != 1) throw new AssertionError();
        });
        check(track, mode, "zip", config.toString(), false, () -> {
          try (Stream<Path> files = Files.list(zip.getPath("/etc"))) {
            if (!files.findFirst().get().toString().equals("/etc/weekly.csv")) throw new AssertionError();
          }
        });
        check(track, mode, "depth-zero", config.toString(), false, () -> {
          try (Stream<Path> names = Files.walk(config, 0)) {
            if (names.count() != 1) throw new AssertionError("enumerated below depth zero");
          }
        });
        check(track, mode, "not-a-directory", page.toString(), false, () -> {
          if (page.toFile().listFiles() != null) throw new AssertionError();
        });
        check(track, mode, "file-list-files", config.toString(), true, () -> {
          if (config.toFile().listFiles() == null) throw new AssertionError();
        });
        final AtomicInteger callbacks = new AtomicInteger();
        boolean fileDenied = check(track, mode, "file-filter", link.toString(), true, () -> {
          if (link.toFile().list((dir, name) -> { callbacks.incrementAndGet(); return false; }).length != 0) {
            throw new AssertionError();
          }
        });
        if (fileDenied != (callbacks.get() == 0)) throw new AssertionError("file filter receipt mismatch");
        callbacks.set(0);
        boolean providerDenied = check(track, mode, "provider-filter", link.toString(), true, () -> {
          try (DirectoryStream<Path> files = link.getFileSystem().provider().newDirectoryStream(link, p -> {
            callbacks.incrementAndGet(); return false;
          })) {
            if (files.iterator().hasNext()) throw new AssertionError();
          }
        });
        if (providerDenied != (callbacks.get() == 0)) throw new AssertionError("provider filter receipt mismatch");
        check(track, mode, "walk", link.toString(), true, () -> {
          try (Stream<Path> files = Files.walk(link, 1, FileVisitOption.FOLLOW_LINKS)) { files.count(); }
        });
        if (parent instanceof SecureDirectoryStream<?>) {
          @SuppressWarnings("unchecked") SecureDirectoryStream<Path> secure = (SecureDirectoryStream<Path>)parent;
          check(track, mode, "relative-open", "selected", true, () -> {
            try (DirectoryStream<Path> ignored = secure.newDirectoryStream(Paths.get("selected"))) { }
          });
          check(track, mode, "relative-ordinary", "orders", false, () -> {
            try (DirectoryStream<Path> files = secure.newDirectoryStream(Paths.get("orders"))) {
              if (!files.iterator().next().getFileName().equals(page.getFileName())) throw new AssertionError();
            }
          });
        }
        if (descriptorCount(config) != initialDescriptors) throw new AssertionError("protected directory descriptors leaked");
      }
    } finally {
      for (Path p : new Path[]{archive, link, page, reports, root}) Files.delete(p);
    }
  }
}
