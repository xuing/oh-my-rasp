package io.ohmyrasp.agent.hookmiss;

/**
 * Where an agent line writes its hook-miss diagnostics: its own event writer, in its own line format. Called on
 * the report's worker thread, never on a class-loading thread.
 */
public interface HookMissSink {
  /**
   * Writes one diagnostic line. {@code diagnostic} is {@code hook_miss} or {@code hook_miss_suppressed};
   * {@code fields} are the line's members after the line's own leading members, as JSON text without braces.
   */
  void write(String diagnostic, String fields);

  /** Marks this thread as doing the agent's own I/O, as the line's writer does; false when it already was. */
  boolean enterOwnIo();

  /** Clears what {@link #enterOwnIo} set when it returned true. */
  void exitOwnIo(boolean entered);
}
