package jetbrains.buildServer.util;

public final class ArchiveUtil {
  private ArchiveUtil() {}

  public static void unpackJava8Zip(String path) {
    saveJava8Entry(path);
  }

  public static void saveJava8Entry(String path) {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeFileWrite(path);
  }
}
