package io.ohmyrasp.agent.file;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Host-path identity and the directory used by a descriptor-relative Unix operation. */
public final class HostFileSystem {
  private HostFileSystem() {}

  public static boolean contains(Object operand) {
    if (!(operand instanceof Path)) return true;
    FileSystem host = FileSystems.getDefault();
    // The built-in host provider takes its own JDK paths. Do not query application path proxies
    // merely to discover that the built-in provider cannot accept them.
    if (host.getClass().getClassLoader() == null && operand.getClass().getClassLoader() != null) return false;
    return ((Path) operand).getFileSystem() == host;
  }

  public static Path absoluteOperand(Path path, int directoryFd) throws IOException {
    if (path.isAbsolute() || directoryFd < 0) return path.toAbsolutePath();
    Path handle = Paths.get("/proc/self/fd", Integer.toString(directoryFd));
    Path directory = Files.readSymbolicLink(handle);
    return directory.isAbsolute() && Files.isSameFile(directory, handle) ? directory.resolve(path) : null;
  }
}
