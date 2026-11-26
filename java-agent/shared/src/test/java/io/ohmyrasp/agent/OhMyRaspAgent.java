package io.ohmyrasp.agent;

import java.lang.instrument.Instrumentation;

/**
 * Test stand-in for the primary line's entry class, which lives in agent-jdk25 and is not on this
 * module's classpath. LauncherEntriesTest starts it through a generated entry and AgentLauncher, which
 * load a line's entry by this name through the system class loader.
 */
public final class OhMyRaspAgent {
  public static int starts;

  private OhMyRaspAgent() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    starts++;
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    starts++;
  }
}
