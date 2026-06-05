package org.springframework.beans.factory.support;

public final class AbstractAutowireCapableBeanFactory {
  private AbstractAutowireCapableBeanFactory() {}

  public static void invokeJava17InitMethod() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("touch", "/tmp/ohmyrasp-activemq46604-success"));
  }

  public static void invokeJava17TikaExternalParserCheck() {
    org.apache.tika.parser.external.ExternalParser.check();
  }

  public static void invokeJava17GetconfClockTick() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "CLK_TCK"));
  }

  public static void invokeJava17LscpuTopology() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("lscpu", "-p=cpu,node"));
  }

  public static void invokeJava17GetconfPageSize() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "PAGE_SIZE"));
  }

  public static void invokeJava17VcgenTemperature() {
    io.ohmyrasp.agent.java17.Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("vcgencmd", "measure_temp"));
  }
}
