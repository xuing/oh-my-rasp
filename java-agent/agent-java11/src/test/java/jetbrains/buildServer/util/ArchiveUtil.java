package jetbrains.buildServer.util;

public final class ArchiveUtil {
  private ArchiveUtil() {}

  public static void unpackJava11Zip(String path) {
    saveJava11Entry(path);
  }

  public static void saveJava11Entry(String path) {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeFileWrite(path);
  }
}
