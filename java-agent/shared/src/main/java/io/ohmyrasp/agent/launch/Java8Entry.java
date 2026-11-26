package io.ohmyrasp.agent.launch;

import java.lang.instrument.Instrumentation;

/**
 * Premain-Class and Agent-Class of the Java 8 line's JARs, and of no other JAR. Each kind of agent
 * JAR has an entry class of its own name: the JVM loads a Premain-Class by name through the system
 * class loader, so a shared name would make a second JAR's premain run the first JAR's class.
 */
public final class Java8Entry {
  private Java8Entry() {}

  public static void premain(String agentArgs, Instrumentation instrumentation) {
    AgentLauncher.start("premain", agentArgs, instrumentation, Java8Entry.class);
  }

  public static void agentmain(String agentArgs, Instrumentation instrumentation) {
    AgentLauncher.start("agentmain", agentArgs, instrumentation, Java8Entry.class);
  }
}
