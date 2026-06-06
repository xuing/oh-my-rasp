package jetbrains.buildServer.web.impl;

public final class Unpacker {
  private Unpacker() {}

  public static void extractJava11(String path) {
    jetbrains.buildServer.util.ArchiveUtil.unpackJava11Zip(path);
  }
}
