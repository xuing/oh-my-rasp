package io.ohmyrasp.agent.runtime;

import java.util.Locale;

/**
 * Local detection mode, the agent's master control switch.
 *
 * <ul>
 *   <li>{@link #OFF} — detection suppressed (no logging, no blocking).
 *   <li>{@link #MONITOR} — detect and record, but never block ("record" mode).
 *   <li>{@link #BLOCK} — detect, record, and block active-request attacks.
 * </ul>
 *
 * <p>A {@code null} mode means "unset": the agent falls back to its legacy
 * policy/flag-driven behavior, which permits blocking. This keeps a freshly
 * installed agent (no control file, no {@code ohmyrasp.mode}) behaving exactly
 * as before while still allowing a daemon or operator to take control.
 */
public enum DetectionMode {
  OFF,
  MONITOR,
  BLOCK;

  /** Parse a mode token, accepting common synonyms; returns {@code null} when unrecognised. */
  public static DetectionMode parse(String value) {
    if (value == null) {
      return null;
    }
    return switch (value.trim().toLowerCase(Locale.ROOT)) {
      case "off", "disabled", "none" -> OFF;
      case "monitor", "record", "observe", "log" -> MONITOR;
      case "block", "blocking", "protect" -> BLOCK;
      default -> null;
    };
  }

  public String token() {
    return name().toLowerCase(Locale.ROOT);
  }
}
