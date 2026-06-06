package jetbrains.buildServer.util;

public final class ArchiveUtil {
  private ArchiveUtil() {}

  public static void unpackJava17Zip(String path) {
    saveJava17Entry(path);
  }

  public static void saveJava17Entry(String path) {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeFileWrite(path);
  }
}
