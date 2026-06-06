package jetbrains.buildServer.web.impl;

public final class BuildServerConfigurator {
  private BuildServerConfigurator() {}

  public static void invokeJava11BundledPluginUnpack(String path) {
    jetbrains.buildServer.web.plugins.files.ServerPluginUnpacker.unpackJava11Plugin(path);
  }

  public static void invokeJava11PluginResourceUnpack(String path) {
    Unpacker.extractJava11(path);
  }
}
