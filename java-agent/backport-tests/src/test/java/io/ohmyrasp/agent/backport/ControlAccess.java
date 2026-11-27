package io.ohmyrasp.agent.backport;

import java.nio.file.Path;

/**
 * Lets the hook tests, which live in the line's package, apply a control document to the started runtime as its
 * poller does. The step stays package-private in RaspRuntime, as the own-I/O marks do (see OwnIoAccess).
 */
public final class ControlAccess {
  private ControlAccess() {}

  /** Applies the control file at {@code path}; a path with no file returns the start-up settings. */
  public static void poll(Path path) {
    RaspRuntime.pollControl(path);
  }
}
