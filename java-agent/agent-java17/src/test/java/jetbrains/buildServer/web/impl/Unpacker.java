package jetbrains.buildServer.web.impl;

public final class Unpacker {
  private Unpacker() {}

  public static void extractJava17(String path) {
    jetbrains.buildServer.util.ArchiveUtil.unpackJava17Zip(path);
  }
}
