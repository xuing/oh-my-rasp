package jetbrains.buildServer.web.impl;

public final class Unpacker {
  private Unpacker() {}

  public static void extractJava8(String path) {
    jetbrains.buildServer.util.ArchiveUtil.unpackJava8Zip(path);
  }
}
