package jetbrains.buildServer.web.plugins.files;

public final class ServerPluginUnpacker {
  private ServerPluginUnpacker() {}

  public static void unpackJava8Plugin(String path) {
    jetbrains.buildServer.plugins.files.PluginFilesUtil.unpackJava8Plugin(path);
  }
}
