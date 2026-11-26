package jetbrains.buildServer.plugins.files;

public final class PluginFilesUtil {
  private PluginFilesUtil() {}

  public static void unpackJava8Plugin(String path) {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeFileWrite(path);
  }
}
