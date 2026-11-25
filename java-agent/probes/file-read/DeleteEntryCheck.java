import java.nio.file.*;
import java.util.Collections;

/** All removals are confined to a fresh temporary fixture or its in-memory archive namespace. */
public class DeleteEntryCheck {
  interface Remove { void run() throws Exception; }

  private static void attempt(String track, String mode, String name, String input, Path entry,
      boolean policy, Remove remove) throws Exception {
    boolean denied = false;
    try (HttpTransportCheck.Scope scope = track.equals("off") ? null : new HttpTransportCheck.Scope(track, input)) {
      remove.run();
    } catch (Exception error) {
      if (!HttpTransportCheck.blocked(error)) throw error;
      denied = true;
    }
    boolean remains = Files.exists(entry, LinkOption.NOFOLLOW_LINKS);
    if (remains != denied) throw new AssertionError("wrong filesystem result for " + name);
    if (!mode.equals("observe") && denied != (policy && mode.equals("block"))) throw new AssertionError(name);
    System.out.println("row," + name + "," + policy + "," + denied + "," + remains);
    if (remains) Files.delete(entry);
  }

  private static void checkPathPolicy() throws Exception {
    Class<?> policy = Class.forName("io.ohmyrasp.agent.policy.AgentPolicy");
    java.lang.reflect.Method install = Class.forName("io.ohmyrasp.agent.hook.OhMyRaspHooks")
        .getMethod("installPolicy", policy, String.class);
    Path root = Files.createTempDirectory("delete-policy");
    Path entry = root.resolve("report.csv");
    try {
      for (String rule : new String[]{"\"hook\":\"deleteFile\",\"action\":\"block\"",
          "\"algorithm\":\"deleteFile_userinput\",\"action\":\"log\""}) {
        Object parsed = policy.getMethod("parse", String.class).invoke(null, "{\"rules\":[{" + rule + "}]}");
        install.invoke(null, parsed, "delete-policy");
        Files.createFile(entry);
        attempt("main", "monitor", "managed-cleanup", entry.toString(), entry, false, () -> Files.delete(entry));
      }
    } finally {
      Files.deleteIfExists(entry);
      Files.delete(root);
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length == 1 && args[0].equals("policy")) { checkPathPolicy(); return; }
    String track = args[0], mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    Path root = args.length > 3 ? Files.createDirectory(Paths.get(args[3])) : Files.createTempDirectory("delete-check");
    Path allowedDir = Files.createDirectory(root.resolve("tenant-reports"));
    Path old = Files.createDirectory(allowedDir.resolve("catalog"));
    Path moved = allowedDir.resolve("moved");
    Path zip = root.resolve("snapshot.zip");
    try (FileSystem archive = FileSystems.newFileSystem(java.net.URI.create("jar:" + zip.toUri()),
             Collections.singletonMap("create", "true"));
         SecureDirectoryStream<Path> directory = (SecureDirectoryStream<Path>) Files.newDirectoryStream(old)) {
      Files.move(old, moved);
      Files.createDirectory(old);
      for (int r = 0; r < rounds; r++) {
        Path entry = root.resolve("weekly.csv");
        Files.createFile(entry);
        attempt(track, mode, "cleanup", "weekly", entry, false, () -> Files.delete(entry));
        Files.createFile(entry);
        attempt(track, mode, "native-separators", entry.toString().replace('/', '\\'), entry, false,
            () -> Files.delete(entry));
        Files.createFile(entry);
        attempt(track, mode, "authorized-report", entry.toString(), entry, false, () -> Files.delete(entry));
        Path sibling = Files.createFile(old.resolve("../monthly.csv"));
        attempt(track, mode, "permitted-sibling", "../monthly.csv", sibling, false, () -> Files.delete(sibling));
        Path guarded = old.resolve("../../weekly.csv");
        Files.createFile(guarded);
        attempt(track, mode, "authorized-absolute-cleanup", guarded.normalize().toString(), guarded, false,
            () -> Files.delete(guarded.normalize()));
        for (int api = 0; api < 3; api++) {
          Files.createFile(guarded);
          final int method = api;
          attempt(track, mode, "host-" + api, "../../weekly.csv", guarded, true, () -> {
            switch (method) {
              case 0: Files.delete(guarded); break;
              case 1: if (!Files.deleteIfExists(guarded)) throw new AssertionError(); break;
              default: guarded.getFileSystem().provider().delete(guarded);
            }
          });
        }
        Path empty = Files.createDirectory(old.resolve("../../empty"));
        attempt(track, mode, "empty-directory", "../../empty", empty, true,
            () -> empty.getFileSystem().provider().delete(empty));
        Path shortcut = Files.createSymbolicLink(old.resolve("archive"), root);
        try {
          Path viaLink = Files.createFile(shortcut.resolve("old.csv"));
          attempt(track, mode, "parent-link", "archive/old.csv", viaLink, true, () -> Files.delete(viaLink));
          Files.createFile(viaLink);
          attempt(track, mode, "absolute-parent-link", viaLink.toString(), viaLink, true, () -> Files.delete(viaLink));
        } finally { Files.delete(shortcut); }
        Path destination = Files.write(root.resolve("linked-report.csv"), new byte[]{9});
        Path alias = Files.createSymbolicLink(old.resolve("copy.csv"), destination);
        attempt(track, mode, "remove-link-in-scope", alias.toString(), alias, false, () -> Files.delete(alias));
        if (Files.readAllBytes(destination)[0] != 9) throw new AssertionError("deleted the target of an in-scope link");
        Files.delete(destination);
        Path missing = old.resolve("../../absent.csv");
        try (HttpTransportCheck.Scope scope = track.equals("off") ? null : new HttpTransportCheck.Scope(track, "../../absent.csv")) {
          if (missing.toFile().delete()) throw new AssertionError("removed absent file");
        }
        System.out.println("row,missing-file-api,false,false,false");
        Path external = Files.createDirectory(root.resolve("tenant-reports-backup"));
        try {
          Path backup = Files.createFile(external.resolve("../backup.csv"));
          attempt(track, mode, "separate-workspace", "../backup.csv", backup, false, () -> Files.delete(backup));
        } finally { Files.delete(external); }
        Path member = Files.createFile(archive.getPath("/weekly.csv"));
        attempt(track, mode, "zip-entry", member.toString(), member, false, () -> Files.delete(member));
        Path target = Files.write(root.resolve("retained.csv"), new byte[]{42});
        Path link = Files.createSymbolicLink(root.resolve("alias.csv"), target);
        attempt(track, mode, "link-only", target.toString(), link, false, () -> Files.delete(link));
        if (Files.readAllBytes(target)[0] != 42) throw new AssertionError("link target changed");
        Files.delete(target);
        Path outside = moved.resolve("../../by-handle.csv");
        Files.createFile(outside);
        attempt(track, mode, "relative-to-handle", "../../by-handle.csv", outside, true,
            () -> directory.deleteFile(Paths.get("../../by-handle.csv")));
        Path relative = Paths.get("weekly.csv");
        Path actual = moved.resolve(relative);
        Files.createFile(actual);
        attempt(track, mode, "renamed-parent", actual.toString(), actual, false, () -> directory.deleteFile(relative));
        Files.createFile(actual);
        Path other = Files.write(old.resolve(relative), new byte[]{7});
        attempt(track, mode, "old-name", other.toString(), actual, false, () -> directory.deleteFile(relative));
        if (Files.readAllBytes(other)[0] != 7) throw new AssertionError("wrong directory descriptor");
        Files.delete(other);
        boolean denied = false;
        try (HttpTransportCheck.Scope scope = track.equals("off") ? null : new HttpTransportCheck.Scope(track, entry.toString())) {
          if (Files.deleteIfExists(entry)) throw new AssertionError("missing file removed");
          try { Files.delete(entry); throw new AssertionError("missing file found"); } catch (NoSuchFileException expected) { }
        } catch (Exception e) { if (!HttpTransportCheck.blocked(e)) throw e; denied = true; }
        if (!mode.equals("observe") && denied) throw new AssertionError("missing file rejected by agent");
        System.out.println("row,missing,false," + denied + ",false");
      }
    } finally {
      for (Path p : new Path[]{zip, old, moved, allowedDir, root}) Files.delete(p);
    }
  }
}
