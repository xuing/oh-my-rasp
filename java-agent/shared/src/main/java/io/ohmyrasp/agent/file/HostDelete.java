package io.ohmyrasp.agent.file;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributeView;

/** Match the selected directory entry. Removing a final symlink does not remove its target. */
public final class HostDelete {
  public enum Basis { NONE, REQUESTED_PATH_ONLY, ESCAPING_ENTRY }
  private static final Path CONFIGURED_ROOT = configuredRoot();
  private final Path operand;
  private final int directoryFd;
  private final boolean relative;
  private final boolean observed;
  private Path absolute;
  private boolean anchorChecked;
  private Path parent;
  private boolean parentChecked;

  public HostDelete(Path operand, int directoryFd, boolean relative, boolean observed) {
    this.operand = operand;
    this.directoryFd = directoryFd;
    this.relative = relative && !operand.isAbsolute();
    this.observed = observed;
  }

  public String path() { return absolute == null ? operand.toString() : absolute.toString(); }

  private static Path configuredRoot() {
    try {
      String value = System.getProperty("ohmyrasp.file.delete_root");
      if (value == null || value.isEmpty()) return null;
      Path path = Paths.get(value);
      return path.isAbsolute() ? path : null;
    } catch (InvalidPathException | SecurityException unavailable) {
      return null;
    }
  }

  public Basis match(String input) {
    if (input == null || input.isEmpty()) return Basis.NONE;
    if ((!observed || CONFIGURED_ROOT == null) && !EscapingPath.mayEscape(input)) return Basis.NONE;
    try {
      Path supplied = Paths.get(input);
      Path name = operand.getFileName();
      if (name == null || ".".equals(name.toString()) || "..".equals(name.toString())
          || !name.equals(supplied.getFileName())) return Basis.NONE;
      if (supplied.isAbsolute()) {
        Path entry = absolute();
        if (!supplied.equals(entry)) return Basis.NONE;
        if (observed && CONFIGURED_ROOT != null && entry.startsWith(CONFIGURED_ROOT)
            && outsideRoot(CONFIGURED_ROOT.toRealPath())) return Basis.ESCAPING_ENTRY;
        return Basis.REQUESTED_PATH_ONLY;
      }
      if (!observed || CONFIGURED_ROOT == null || !operand.endsWith(supplied)) return Basis.NONE;
      Path base = absolute();
      for (int i = 0; base != null && i < supplied.getNameCount(); i++) base = base.getParent();
      if (base == null) return Basis.NONE;
      Path root = CONFIGURED_ROOT.toRealPath();
      return base.toRealPath().startsWith(root) && outsideRoot(root) ? Basis.ESCAPING_ENTRY : Basis.NONE;
    } catch (IOException | InvalidPathException | SecurityException unavailable) {
      return Basis.NONE;
    }
  }

  private boolean outsideRoot(Path root) throws IOException {
    Path directory = parent();
    return directory != null && !directory.startsWith(root);
  }

  private Path absolute() throws IOException {
    if (!anchorChecked) {
      anchorChecked = true;
      if (!relative) absolute = operand.toAbsolutePath();
      else if (directoryFd >= 0) {
        Path handle = Paths.get("/proc/self/fd", Integer.toString(directoryFd));
        Path directory = Files.readSymbolicLink(handle);
        if (directory.isAbsolute() && Files.isSameFile(directory, handle)) absolute = directory.resolve(operand);
      }
    }
    return absolute;
  }

  private Path parent() throws IOException {
    if (!parentChecked) {
      parentChecked = true;
      Path entry = absolute();
      if (entry != null && entry.getParent() != null) {
        parent = entry.getParent().toRealPath();
      }
    }
    return parent;
  }

  public static boolean hasEntry(SecureDirectoryStream<Path> directory, Path operand, boolean removeDirectory) {
    try {
      BasicFileAttributeView view = directory.getFileAttributeView(operand, BasicFileAttributeView.class,
          LinkOption.NOFOLLOW_LINKS);
      return view != null && view.readAttributes().isDirectory() == removeDirectory;
    } catch (IOException | SecurityException | UnsupportedOperationException unavailable) {
      return false;
    }
  }
}
