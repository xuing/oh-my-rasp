package jetbrains.buildServer.web.impl;

public final class BuildServerConfigurator {
  private BuildServerConfigurator() {}

  public static void invokeJava8BundledPluginUnpack(String path) {
    jetbrains.buildServer.web.plugins.files.ServerPluginUnpacker.unpackJava8Plugin(path);
  }

  public static void invokeJava8PluginResourceUnpack(String path) {
    Unpacker.extractJava8(path);
  }
}
