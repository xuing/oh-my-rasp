package jetbrains.buildServer.web.plugins.files;

public final class ServerPluginUnpacker {
  private ServerPluginUnpacker() {}

  public static void unpackJava11Plugin(String path) {
    jetbrains.buildServer.plugins.files.PluginFilesUtil.unpackJava11Plugin(path);
  }
}
