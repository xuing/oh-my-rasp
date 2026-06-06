package jetbrains.buildServer.web.impl;

public final class BuildServerConfigurator {
  private BuildServerConfigurator() {}

  public static void invokeJava17BundledPluginUnpack(String path) {
    jetbrains.buildServer.web.plugins.files.ServerPluginUnpacker.unpackJava17Plugin(path);
  }

  public static void invokeJava17PluginResourceUnpack(String path) {
    Unpacker.extractJava17(path);
  }
}
