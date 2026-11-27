package io.ohmyrasp.agent.hook;

import java.util.List;
import java.util.Map;

/**
 * One pass of the hooks that run on every request, on a harmless input, at start. Preloading loads and initialises
 * every class; what is left for the first hooked call is what only running code does: linking its lambdas and method
 * references, loading the JDK's own stream and regex classes it first uses, compiling nothing yet compiled. Doing
 * that here keeps it off the first request's thread.
 *
 * <p>No side effect on the application: each input is a constant held in memory, no hook called here reads a file,
 * opens a socket or starts a process, and a hook writes an event only for a detection, which none of these inputs
 * is (WarmupTest asserts the event log is empty). A failure is ignored: the warm-up is an optimisation, not a
 * condition of starting. Run it before the transformer is registered, so no instrumented call can reach it.
 */
public final class Warmup {
  private Warmup() {}

  private static final int STEPS = 5;

  /** Calls each hook once with a harmless input; never throws. */
  public static void run() {
    for (int step = 0; step < STEPS; step++) {
      try {
        call(step);
      } catch (Throwable ignored) {
        // Nothing to report: the hook did what it would for any input, and the start goes on.
      }
    }
  }

  private static void call(int step) {
    Map<String, String> headers =
        Map.of("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)", "Accept", "text/html", "Host", "localhost");
    switch (step) {
      case 0 -> OhMyRaspHooks.beforeSyntheticHttpRequest("GET", "/index.html", "page=2&sort=name",
          Map.of("page", List.of("2"), "sort", List.of("name")), headers);
      case 1 -> OhMyRaspHooks.beforeSyntheticHttpRequestWithBody("POST", "/api/items", "",
          Map.of("name", List.of("widget")), headers, "name=widget&count=3");
      case 2 -> OhMyRaspHooks.beforeSyntheticHttpRequestWithBody("POST", "/api/items", "", Map.of(), headers,
          "{\"name\":\"widget\",\"tags\":[\"a\",\"b\"],\"count\":3}");
      case 3 -> OhMyRaspHooks.beforeSql("SELECT id, name FROM items WHERE id = 1");
      case 4 -> OhMyRaspHooks.beforeDeserializationClass("java.lang.String");
      default -> { }
    }
  }
}
