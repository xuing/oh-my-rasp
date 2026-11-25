package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.util.WeakOwners;
import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

/** Directory content comes from the filesystem that performed the enumeration. */
public final class HostDirectory {
  private static final String[] ROOTS = {"/etc", "/proc", "/root"};
  // The native return and the File API handoff occur on the same thread. A backend
  // may reuse an empty array, so the result alone cannot identify the listing.
  private static final ThreadLocal<Substitution> SUBSTITUTION = new ThreadLocal<Substitution>();
  private static final class Substitution {
    final WeakReference<File> original;
    final WeakReference<String[]> entries;
    final File selected;
    Substitution(File original, String[] entries, File selected) {
      this.original = new WeakReference<File>(original);
      this.entries = new WeakReference<String[]>(entries);
      this.selected = selected;
    }
  }

  private static final WeakOwners<Walk> ORIGINS = new WeakOwners<Walk>();
  private static final ThreadLocal<Visit> CURRENT = new ThreadLocal<Visit>();
  private static final Walk BACKGROUND = new Walk(null, false);

  public static final class Walk {
    public final Object origin;
    public final boolean selected;
    private Walk(Object origin, boolean selected) { this.origin = origin; this.selected = selected; }
  }

  private static final class Visit {
    final Path path;
    final Walk walk;
    final Visit parent;
    Visit(Path path, Walk walk, Visit parent) { this.path = path; this.walk = walk; this.parent = parent; }
  }

  public static void submitted(Object walker, Object origin, boolean selected) {
    if (origin != null) ORIGINS.put(walker, new Walk(origin, selected));
  }

  public static void visiting(Object walker, Path path, boolean activeRequest) {
    Walk walk = ORIGINS.get(walker);
    Visit parent = CURRENT.get();
    if (walk != null || activeRequest || parent != null) {
      CURRENT.set(new Visit(path, walk == null ? BACKGROUND : walk, parent));
    }
  }

  public static void visited() {
    Visit visit = CURRENT.get();
    if (visit == null) return;
    if (visit.parent == null) CURRENT.remove();
    else CURRENT.set(visit.parent);
  }

  public static void closed(Object walker) { ORIGINS.remove(walker); }

  public static Walk origin(Path opened) {
    Visit visit = CURRENT.get();
    return visit != null && visit.path == opened ? visit.walk : null;
  }

  private HostDirectory() {}

  public static void listed(File used, String[] entries, File original) {
    if (entries != null && used != original) SUBSTITUTION.set(new Substitution(original, entries, used));
    else if (SUBSTITUTION.get() != null) SUBSTITUTION.remove();
  }

  public static File selectedFile(File original, String[] entries) {
    Substitution handoff = SUBSTITUTION.get();
    if (handoff == null) return original;
    SUBSTITUTION.remove();
    return entries != null && handoff.original.get() == original && handoff.entries.get() == entries
        ? handoff.selected : original;
  }

  public static boolean selected(String path, List<String> inputs, boolean descriptorRelative) {
    if (inputs == null || path == null || path.isEmpty()) return false;
    if (inputs.contains(path)) return true;
    return !descriptorRelative && HostReadPath.selected(path, inputs);
  }

  private static boolean protectedName(String path) {
    for (String root : ROOTS) if (root.equals(path)) return true;
    return false;
  }

  public static String namedRoot(String path) {
    return File.separatorChar == '/' && protectedName(path) ? path : "";
  }

  /** A descriptor-relative open has no process-working-directory based absolute name. */
  public static String protectedRoot(String path, DirectoryStream<?> opened, boolean descriptorRelative) {
    if (File.separatorChar != '/' || path == null || path.isEmpty()) return "";
    if (!(opened instanceof SecureDirectoryStream<?>)) {
      if (descriptorRelative) return "";
      String lexical = HostReadPath.location(path);
      if (protectedName(lexical) && HostReadPath.confirmsLocation(path)) return lexical;
      return namedRoot(HostReadPath.OpenPolicy.FOLLOW.resolvedLocation(path));
    }
    try {
      BasicFileAttributeView view = ((SecureDirectoryStream<?>) opened).getFileAttributeView(BasicFileAttributeView.class);
      if (view == null) return "";
      Object key = view.readAttributes().fileKey();
      if (key == null) return "";
      for (String root : ROOTS) {
        try {
          BasicFileAttributes named = Files.readAttributes(Paths.get(root), BasicFileAttributes.class);
          if (named.isDirectory() && key.equals(named.fileKey())) return root;
        } catch (IOException | SecurityException unavailable) {
          // A named root can be absent in this process's namespace.
        }
      }
    } catch (IOException | SecurityException | UnsupportedOperationException | java.nio.file.ClosedDirectoryStreamException unavailable) {
      // No verified descriptor identity.
    }
    return "";
  }

  public static void closeDenied(DirectoryStream<?> opened, RuntimeException decision) {
    if (opened != null) {
      try { opened.close(); }
      catch (IOException | RuntimeException failure) { decision.addSuppressed(failure); }
    }
  }
}
