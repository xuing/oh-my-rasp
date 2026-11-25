import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Only private temporary files and ZIP entries are written. No generated text is executed. */
public final class WriteNamespaceCheck {
  interface Write { void run() throws Exception; }
  private static final byte[] REPORT = "weekly".getBytes(StandardCharsets.UTF_8);

  static void attempt(String track, String mode, String name, String input, Path target,
      byte[] expected, boolean policy, Write write) throws Exception {
    Path log = Paths.get(System.getProperty("ohmyrasp.log"));
    byte[] prior = Files.exists(target) ? Files.readAllBytes(target) : null;
    long before = Files.exists(log) ? Files.size(log) : 0;
    boolean denied = false;
    try (HttpTransportCheck.Scope ignored = new HttpTransportCheck.Scope(track, input)) {
      write.run();
    } catch (Exception failure) {
      if (!HttpTransportCheck.blocked(failure)) throw failure;
      denied = true;
    }
    byte[] result = Files.exists(target) ? Files.readAllBytes(target) : null;
    if (!Arrays.equals(result, denied ? prior : expected))
      throw new AssertionError("incorrect file result for " + name);
    long after = Files.exists(log) ? Files.size(log) : 0;
    System.out.println("row," + name + "," + denied + "," + before + "," + after);
    if (!"observe".equals(mode) && denied != (policy && "block".equals(mode))) throw new AssertionError(name);
  }

  static byte[] archive(String name) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
      zip.putNextEntry(new ZipEntry(name));
      zip.write(REPORT);
    }
    return bytes.toByteArray();
  }

  static final class DisplayEntry extends ZipEntry {
    int calls;
    DisplayEntry(String name) { super(name); }
    @Override public String getName() { calls++; return "display-only.txt"; }
  }

  private static void primaryArchiveSources(String mode, Path work) throws Exception {
    Path target = work.resolve("source.txt"), source = work.resolve("input.zip"), absent = work.resolve("absent.txt");
    byte[] packed = archive(target.toString());
    Files.write(source, packed);
    try (ZipFile input = new ZipFile(source.toFile())) {
      DisplayEntry missing = new DisplayEntry(absent.toString());
      attempt("main", mode, "missing-lookup", "weekly", absent, REPORT, false, () -> {
        if (input.getInputStream(missing) != null) throw new AssertionError("unexpected member");
        Files.write(absent, REPORT);
      });
      if (missing.calls != 0) throw new AssertionError("agent rendered missing member");
      DisplayEntry selected = new DisplayEntry(target.toString());
      attempt("main", mode, "resolved-lookup", "weekly", target, REPORT, true, () -> {
        try (InputStream member = input.getInputStream(selected)) {
          if (member == null) throw new AssertionError("missing member");
          try (HttpTransportCheck.Scope nested = new HttpTransportCheck.Scope("main", "monthly", "/nested")) {
            Files.write(target, REPORT);
            Files.delete(target);
          }
          try (SeekableByteChannel out = target.getFileSystem().provider().newByteChannel(target,
              EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
            out.write(ByteBuffer.wrap(REPORT));
          }
        }
      });
      if (selected.calls != 0) throw new AssertionError("agent rendered selected member");
      Files.deleteIfExists(target);
      DisplayEntry[] read = new DisplayEntry[1];
      attempt("main", mode, "closed-reader", "weekly", target, REPORT, false, () -> {
        try (ZipInputStream reader = new ZipInputStream(new ByteArrayInputStream(packed)) {
          @Override protected ZipEntry createZipEntry(String name) { return read[0] = new DisplayEntry(name); }
        }) {
          if (reader.getNextEntry() != read[0]) throw new AssertionError("wrong published member");
        }
        Files.write(target, REPORT);
      });
      if (read[0] == null || read[0].calls != 0) throw new AssertionError("agent called application getter");
      Files.delete(target);
      attempt("main", mode, "closed-during-nested-request", "weekly", target, REPORT, false, () -> {
        try (ZipInputStream outer = new ZipInputStream(new ByteArrayInputStream(packed))) {
          if (outer.getNextEntry() == null) throw new AssertionError("no archive entry");
          try (HttpTransportCheck.Scope nested = new HttpTransportCheck.Scope("main", "monthly", "/nested")) {
            outer.closeEntry();
          }
          Files.write(target, REPORT);
        }
      });
    } finally {
      Files.deleteIfExists(absent);
      Files.deleteIfExists(target);
      Files.deleteIfExists(source);
    }
  }

  public static void main(String[] args) throws Exception {
    String track = args[0], mode = args[1];
    Path temp = Files.createTempDirectory("report-namespace"), zipFile = temp.resolve("exports.zip");
    Path hostDir = Files.createDirectories(temp.resolve("webapps")), script = hostDir.resolve("weekly.jsp");
    Path received = temp.resolve("received.txt"), generated = temp.resolve("rendered.tmp");
    Path existing = hostDir.resolve("existing.jsp");
    Path old = Files.createDirectory(temp.resolve("catalog")), moved = temp.resolve("moved");
    Path leaf = Paths.get("chart.txt"), actual = moved.resolve(leaf), other = old.resolve(leaf);

    try (FileSystem zip = FileSystems.newFileSystem(URI.create("jar:" + zipFile.toUri()),
        Collections.singletonMap("create", "true"))) {
      // The JDK itself asks for the filesystem once before ZIP FS rejects a foreign path type.
      int[] gets = {0};
      Path proxy = (Path) java.lang.reflect.Proxy.newProxyInstance(WriteNamespaceCheck.class.getClassLoader(),
          new Class<?>[]{Path.class}, (receiver, method, values) -> {
            if (method.getName().equals("getFileSystem")) { gets[0]++; return zip; }
            throw new AssertionError("unexpected callback on a foreign path: " + method.getName());
          });
      try (OutputStream ignored = Files.newOutputStream(proxy)) {
        throw new AssertionError("ZIP provider unexpectedly accepted a proxy");
      } catch (ProviderMismatchException expected) {
        if (gets[0] != 1) throw new AssertionError("repeated path getter");
      }
      if (track.equals("main")) primaryArchiveSources(mode, temp);
      Path members = Files.createDirectories(zip.getPath("/webapps"));
      Path member = members.resolve("weekly.jsp");
      attempt(track, mode, "zip-bytes", "weekly", member, REPORT, false, () -> Files.write(member, REPORT));
      Path copied = members.resolve("copy.jsp");
      attempt(track, mode, "zip-copy", "weekly", copied, REPORT, false,
          () -> Files.copy(new ByteArrayInputStream(REPORT), copied));
      if (track.equals("main")) {
        String operation = "system(\"printf weekly\")";
        String line = "value = " + operation;
        Path folder = Files.createDirectories(zip.getPath("/tmp/rendered"));
        Path bytes = folder.resolve("bytes.tmp"), encoded = folder.resolve("encoded.tmp"), lines = folder.resolve("lines.tmp");
        byte[] utf8 = line.getBytes(StandardCharsets.UTF_8);
        attempt(track, mode, "zip-generated-bytes", operation, bytes, utf8, false, () -> Files.write(bytes, utf8));
        attempt(track, mode, "host-generated-bytes", operation, generated, utf8, true, () -> Files.write(generated, utf8));
        attempt(track, mode, "zip-generated-text", operation, encoded, line.getBytes(StandardCharsets.UTF_16LE), false,
            () -> Files.class.getMethod("writeString", Path.class, CharSequence.class, java.nio.charset.Charset.class,
                OpenOption[].class).invoke(null, encoded, line, StandardCharsets.UTF_16LE, new OpenOption[0]));
        attempt(track, mode, "zip-generated-lines", operation, lines, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
            false, () -> Files.write(lines, Collections.singleton(line), StandardCharsets.UTF_8));
      }
      attempt(track, mode, "host-bytes", "weekly", script, REPORT, true, () -> Files.write(script, REPORT));
      try (SeekableByteChannel seed = existing.getFileSystem().provider().newByteChannel(existing,
          EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
        seed.write(ByteBuffer.wrap(new byte[]{7}));
      }
      attempt(track, mode, "host-replace", "weekly", existing, REPORT, true,
          () -> Files.copy(new ByteArrayInputStream(REPORT), existing, StandardCopyOption.REPLACE_EXISTING));
      String spelling = received.toString();
      byte[] packed = archive(spelling);
      Path virtual = zip.getPath(spelling);
      Files.createDirectories(virtual.getParent());
      attempt(track, mode, "virtual-member", "weekly", virtual, REPORT, false, () -> {
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(packed))) {
          String name = in.getNextEntry().getName();
          if (!name.equals(spelling)) throw new AssertionError();
          Files.copy(in, zip.getPath(name));
          // A later host write in this same request must not inherit the consumed member.
          Files.write(received, REPORT);
          if (!Arrays.equals(Files.readAllBytes(received), REPORT)) throw new AssertionError("stale member");
          Files.delete(received);
        }
      });
      // The target is fixed by the fixture. The observed member name and host operand coincide.
      attempt(track, mode, "host-channel", "weekly", received, REPORT, true, () -> {
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(packed))) {
          if (!spelling.equals(in.getNextEntry().getName())) throw new AssertionError();
          try (SeekableByteChannel channel = received.getFileSystem().provider().newByteChannel(received,
              EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
            channel.write(ByteBuffer.wrap(REPORT));
          }
        }
      });
      try (SecureDirectoryStream<Path> directory = (SecureDirectoryStream<Path>) Files.newDirectoryStream(old)) {
        Files.move(old, moved);
        Files.createDirectory(old);
        for (boolean selected : new boolean[]{false, true}) {
          String observed = (selected ? actual : other).toString();
          byte[] input = archive(observed);
          attempt(track, mode, selected ? "bound-directory" : "old-directory", "weekly", actual, REPORT, selected, () -> {
            try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(input))) {
              if (!observed.equals(in.getNextEntry().getName())) throw new AssertionError("wrong entry");
              try (SeekableByteChannel channel = directory.newByteChannel(leaf,
                  EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW))) {
                channel.write(ByteBuffer.wrap(REPORT));
              }
            }
          });
          if (Files.exists(other)) throw new AssertionError("wrong directory identity");
          Files.deleteIfExists(actual);
        }
      }
    } finally {
      for (Path p : new Path[]{actual, other, old, moved, received, generated, existing, script, hostDir, zipFile, temp}) Files.deleteIfExists(p);
    }
  }
}
