package io.ohmyrasp.agent.process;

import io.ohmyrasp.agent.rules.general.RequestShellSyntax;
import io.ohmyrasp.agent.rules.product.rocketmq.RocketMqFilterServer;

/** Source evidence for the POSIX shell-operator policy at a process sink. */
public enum ShellControlSource {
  REQUEST("request_shell_syntax", "Request input controls syntax in the shell program"),
  CONFIGURATION("configuration_launcher", "A runtime configuration launcher passed shell operators to the process API");

  public final String basis;
  public final String message;

  ShellControlSource(String basis, String message) {
    this.basis = basis;
    this.message = message;
  }

  public static ShellControlSource classify(
      PosixShellCommand program, Iterable<String> requestValues, StackTraceElement[] stack) {
    if (!program.hasOperator()) {
      return null;
    }
    if (RequestShellSyntax.matches(program, requestValues)) return REQUEST;
    return RocketMqFilterServer.directlyCallsProcessApi(stack) ? CONFIGURATION : null;
  }
}
