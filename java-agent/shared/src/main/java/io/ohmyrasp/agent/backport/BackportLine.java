package io.ohmyrasp.agent.backport;

import java.util.Locale;

/**
 * What differs between the backport lines (agent-java8, agent-java11, agent-java17), which share the runtime
 * ({@link RaspRuntime}) and the decisions in this package. Each line has one subclass, {@code Java<N>RaspLine},
 * which makes and recognises the line's own block exception.
 *
 * <p>The line's entry class installs its line once, before anything in this package runs, and a JVM runs one line:
 * the launcher starts one. Nothing here falls back to a default line: until a line is installed, {@link #current}
 * throws.
 */
public abstract class BackportLine {
  /** {@code java8}: the line's token. */
  public final String token;
  /** {@code Java 8}: the line's name in event and block messages. */
  public final String displayName;
  /** {@code java8_}: the prefix of the line's rule ids. A few families are emitted without it. */
  public final String rulePrefix;
  /** {@code ohmyrasp.java8.}: the prefix of the line's own system properties. */
  public final String propertyPrefix;
  /** {@code OHMYRASP_JAVA8_}: the prefix of the line's own environment variables. */
  public final String environmentPrefix;
  /** {@code [OHMYRASP-JAVA8]}: the prefix of what the line prints to standard error. */
  public final String logPrefix;
  /** The line's entry class, which the runtime uses to find the agent's own JAR. */
  public final String entryClass;
  /** The name of the thread that polls the control file. */
  public final String controlThreadName;
  /** The name of the thread that writes queued events. */
  public final String writerThreadName;
  /** {@code ohmyrasp.java8.log}: the log target for this line only. */
  public final String logProperty;
  /** {@code ohmyrasp.java8.block}: the legacy block flag. */
  public final String blockProperty;
  /** {@code OHMYRASP_JAVA8_BLOCK}: the legacy block flag in the environment. */
  public final String blockEnvironment;

  private static final Object INSTALL_LOCK = new Object();
  private static volatile BackportLine installed;

  /** @param release the line's Java release, {@code 8}, {@code 11} or {@code 17} */
  protected BackportLine(String release) {
    if (release == null || !release.matches("[0-9]{1,2}")) {
      throw new IllegalArgumentException("not a Java release: " + release);
    }
    String upper = ("JAVA" + release).toUpperCase(Locale.ROOT);
    token = "java" + release;
    displayName = "Java " + release;
    rulePrefix = token + "_";
    propertyPrefix = "ohmyrasp." + token + ".";
    environmentPrefix = "OHMYRASP_" + upper + "_";
    logPrefix = "[OHMYRASP-" + upper + "]";
    entryClass = "io.ohmyrasp.agent." + token + ".OhMyRaspJava" + release + "Agent";
    controlThreadName = "ohmyrasp-" + token + "-control";
    writerThreadName = "ohmyrasp-" + token + "-writer";
    logProperty = propertyPrefix + "log";
    blockProperty = propertyPrefix + "block";
    blockEnvironment = environmentPrefix + "BLOCK";
  }

  /** A new block exception of this line, carrying {@code message}. */
  public abstract RuntimeException block(String message);

  /** Whether {@code thrown} is this line's block exception. */
  public abstract boolean isBlock(Throwable thrown);

  /**
   * Installs {@code line} as the line of this JVM. Installing the same line again does nothing, so an entry class
   * that runs twice (premain, then agentmain) starts once; installing another line fails.
   */
  public static void install(BackportLine line) {
    if (line == null) {
      throw new IllegalArgumentException("no line");
    }
    synchronized (INSTALL_LOCK) {
      BackportLine current = installed;
      if (current == null) {
        installed = line;
      } else if (!current.token.equals(line.token)) {
        throw new IllegalStateException(
            "backport line " + current.token + " is installed; " + line.token + " cannot start in the same JVM");
      }
    }
  }

  /** The installed line. Throws when no line is installed: nothing here may run for a default line. */
  public static BackportLine current() {
    BackportLine line = installed;
    if (line == null) {
      throw new IllegalStateException(
          "no backport line is installed: the line's entry class installs it before anything in "
              + "io.ohmyrasp.agent.backport runs");
    }
    return line;
  }
}
