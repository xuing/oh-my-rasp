package org.apache.tika.parser.external;

public final class ExternalParser {
  private ExternalParser() {}

  public static void check() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {"ffmpeg", "-version"});
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {"exiftool", "-ver"});
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeRuntimeExecArray(
        new String[] {"tesseract"});
  }
}
