package io.ohmyrasp.agent.rules.general;

import io.ohmyrasp.agent.process.PosixShellCommand;

/** Correlate request values with control syntax in the actual shell program. */
public final class RequestShellSyntax {
  private RequestShellSyntax() {}

  public static boolean matches(PosixShellCommand program, Iterable<String> values) {
    if (program == null || !program.hasOperator() || values == null) return false;
    for (String value : values) {
      if (program.containsControlFrom(value)) return true;
    }
    return false;
  }
}
