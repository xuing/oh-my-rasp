package jetbrains.buildServer.web.plugins.files;

public final class ServerPluginUnpacker {
  private ServerPluginUnpacker() {}

  public static void unpackJava17Plugin(String path) {
    jetbrains.buildServer.plugins.files.PluginFilesUtil.unpackJava17Plugin(path);
  }
}
