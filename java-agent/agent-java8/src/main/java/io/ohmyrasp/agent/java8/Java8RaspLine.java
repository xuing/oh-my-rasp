package io.ohmyrasp.agent.java8;

import io.ohmyrasp.agent.backport.BackportHooks;
import io.ohmyrasp.agent.backport.BackportLine;
import io.ohmyrasp.agent.backport.RaspRuntime;

/**
 * The Java 8 line of the shared backport runtime and decisions (io.ohmyrasp.agent.backport): its tokens, from
 * the release, and its block exception, {@link Java8RaspBlockException}.
 */
public final class Java8RaspLine extends BackportLine {
  private Java8RaspLine() {
    super("8");
  }

  public RuntimeException block(String message) {
    return new Java8RaspBlockException(message);
  }

  public boolean isBlock(Throwable thrown) {
    return thrown instanceof Java8RaspBlockException;
  }

  /**
   * Installs this line, initialises the classes the hooks use first (the shared decisions, this line's hooks class
   * and its block exception) and starts the shared runtime. The entry class calls it after it appends the agent JAR to
   * the bootstrap search and before it registers any transformer, so the classes here are defined by the loader
   * the hooks run in and no hook does this work on an application thread. A second call does nothing.
   */
  public static void start() {
    BackportLine.install(new Java8RaspLine());
    // What can fail comes first; the runtime starts its threads last and publishes that it has started only when
    // all of this has succeeded. A failed start leaves no thread and can be retried.
    BackportHooks.initialise();
    BackportLine.initialise(Java8RaspHooks.class, Java8RaspBlockException.class);
    RaspRuntime.start();
  }
}
