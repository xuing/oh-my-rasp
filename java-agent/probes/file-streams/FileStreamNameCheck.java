import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.Collections;

/** Exercise file contents and stream metadata in a private directory. */
public final class FileStreamNameCheck {
  private static void install(String selector, String action) throws Exception {
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    String json = "{\"rules\":[{" + selector + ",\"action\":\"" + action + "\"}]}";
    Object value = policy.getMethod("parse", String.class).invoke(null, json);
    Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks").getMethod("installPolicy", policy, String.class)
        .invoke(null, value, "stream-check");
  }

  private static void requireByte(Path file, int expected) throws Exception {
    byte[] bytes = Files.readAllBytes(file);
    if (bytes.length != 1 || bytes[0] != expected) throw new AssertionError("file content changed");
  }

  private static void checkBasePolicy(Path work, String suffix) throws Exception {
    Path file = work.resolve("weekly.jsp");
    try {
      try (FileOutputStream out = new FileOutputStream(file + suffix)) { out.write(7); }
      throw new AssertionError("base-file policy did not block");
    } catch (RuntimeException expected) {
      if (!HttpTransportCheck.blocked(expected)) throw expected;
      if (Files.exists(file)) throw new AssertionError("protected base file was created");
    } finally { Files.deleteIfExists(file); }
  }

  private static void windows(Path work) throws Exception {
    Path file = Files.write(work.resolve("weekly.txt"), new byte[]{1});
    try {
      try (FileOutputStream out = new FileOutputStream(file + "::$DATA")) { out.write(42); }
      requireByte(file, 42);
      checkBasePolicy(work, "::$DATA");
      UserDefinedFileAttributeView attributes = Files.getFileAttributeView(file, UserDefinedFileAttributeView.class);
      attributes.write("author", ByteBuffer.wrap(new byte[]{1}));
      install("\"algorithm\":\"writeFile_NTFS\"", "log");
      attributes.write("author", ByteBuffer.wrap(new byte[]{2}));
      install("\"algorithm\":\"writeFile_NTFS\"", "block");
      try {
        attributes.write("author", ByteBuffer.wrap(new byte[]{3}));
        throw new AssertionError("named-stream policy did not block");
      } catch (RuntimeException expected) {
        if (!HttpTransportCheck.blocked(expected)) throw expected;
      }
      try (RandomAccessFile read = new RandomAccessFile(file + ":author", "r")) {
        if (read.read() != 2) throw new AssertionError("wrong read-only stream value");
      }
      try (RandomAccessFile write = new RandomAccessFile(file + ":author", "rw")) {
        throw new AssertionError("writable random-access stream was allowed");
      } catch (RuntimeException expected) {
        if (!HttpTransportCheck.blocked(expected)) throw expected;
      }
      ByteBuffer data = ByteBuffer.allocate(1);
      if (attributes.read("author", data) != 1 || data.get(0) != 2) throw new AssertionError("wrong attribute value");
      requireByte(file, 42);
    } finally { Files.deleteIfExists(file); }
  }

  private static void posix(Path work) throws Exception {
    Path output = work.resolve("weekly.txt::$DATA"), index = work.resolve("index.txt::$INDEX");
    try {
      checkBasePolicy(work, "");
      install("\"algorithm\":\"writeFile_NTFS\"", "block");
      try (FileOutputStream stream = new FileOutputStream(output.toFile())) { stream.write(42); }
      Files.write(index, new byte[]{7});
      requireByte(output, 42);
      requireByte(index, 7);
    } finally { Files.deleteIfExists(output); Files.deleteIfExists(index); }
  }

  public static void main(String[] args) throws Exception {
    Path work = Files.createTempDirectory("stream-names");
    Path archive = work.resolve("reports.zip");
    try (HttpTransportCheck.Scope scope = new HttpTransportCheck.Scope("main", "weekly")) {
      install("\"hook\":\"writeFile\"", "block");
      if (File.separatorChar == '\\') windows(work); else posix(work);
      try (FileSystem zip = FileSystems.newFileSystem(URI.create("jar:" + archive.toUri()),
          Collections.singletonMap("create", "true"))) {
        Path member = zip.getPath("/weekly.txt::$DATA");
        Files.write(member, new byte[]{9});
        requireByte(member, 9);
      }
    } finally { Files.deleteIfExists(archive); Files.delete(work); }
  }
}
