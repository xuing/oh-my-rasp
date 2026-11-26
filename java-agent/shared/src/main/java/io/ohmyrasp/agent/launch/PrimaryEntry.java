package io.ohmyrasp.agent.launch;

import java.lang.instrument.Instrumentation;

/**
 * Premain-Class and Agent-Class of the primary line's JARs (ohmyrasp-agent.jar and
 * ohmyrasp-jdk25.jar), and of no other JAR. Each kind of agent JAR has an entry class of its own
 * name: the JVM loads a Premain-Class by name through the system class loader, so a shared name
 * would make a second JAR's premain run the first JAR's class.
 */
public final class PrimaryEntry {
  private PrimaryEntry() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    AgentLauncher.start("premain", agentArgs, instrumentation, PrimaryEntry.class);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    AgentLauncher.start("agentmain", agentArgs, instrumentation, PrimaryEntry.class);
  }
}
