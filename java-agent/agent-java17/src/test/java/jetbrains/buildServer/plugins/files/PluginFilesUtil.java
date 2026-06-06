package jetbrains.buildServer.plugins.files;

public final class PluginFilesUtil {
  private PluginFilesUtil() {}

  public static void unpackJava17Plugin(String path) {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeFileWrite(path);
  }
}
