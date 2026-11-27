package io.ohmyrasp.agent.java11;

import io.ohmyrasp.agent.backport.BackportHooks;
import io.ohmyrasp.agent.backport.BackportLine;
import io.ohmyrasp.agent.backport.RaspRuntime;

/**
 * The Java 11 line of the shared backport runtime and decisions (io.ohmyrasp.agent.backport): its tokens, from
 * the release, and its block exception, {@link Java11RaspBlockException}.
 */
public final class Java11RaspLine extends BackportLine {
  private Java11RaspLine() {
    super("11");
  }

  public RuntimeException block(String message) {
    return new Java11RaspBlockException(message);
  }

  public boolean isBlock(Throwable thrown) {
    return thrown instanceof Java11RaspBlockException;
  }

  /**
   * Installs this line, initialises the classes the hooks use first (the shared decisions, this line's hooks class
   * and its block exception) and starts the shared runtime. The entry class calls it after it appends the agent JAR to
   * the bootstrap search and before it registers any transformer, so the classes here are defined by the loader
   * the hooks run in and no hook does this work on an application thread. A second call does nothing.
   *
   * @return true when this call started the runtime
   */
  public static boolean start() {
    BackportLine.install(new Java11RaspLine());
    // What can fail comes first; the runtime starts its threads last and publishes that it has started only when
    // all of this has succeeded. A failed start leaves no thread and can be retried.
    BackportHooks.initialise();
    BackportLine.initialise(Java11RaspHooks.class, Java11RaspBlockException.class);
    return RaspRuntime.start();
  }
}
