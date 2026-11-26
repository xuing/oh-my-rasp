package io.ohmyrasp.agent.backport;

/**
 * Lets the hook tests, which live in the line's package, mark the agent's own I/O as the runtime does. The
 * marks stay package-private in RaspRuntime: on the bootstrap search, a public method that turns detection off
 * for the calling thread would be one an injected expression could call.
 */
public final class OwnIoAccess {
  private OwnIoAccess() {}

  public static boolean enterOwnIo() {
    return RaspRuntime.enterOwnIo();
  }

  public static void exitOwnIo(boolean entered) {
    RaspRuntime.exitOwnIo(entered);
  }

  public static boolean inOwnIo() {
    return RaspRuntime.inOwnIo();
  }
}
