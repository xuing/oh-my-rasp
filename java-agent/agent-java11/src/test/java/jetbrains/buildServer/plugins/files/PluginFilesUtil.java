package jetbrains.buildServer.plugins.files;

public final class PluginFilesUtil {
  private PluginFilesUtil() {}

  public static void unpackJava11Plugin(String path) {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeFileWrite(path);
  }
}
