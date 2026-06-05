package org.springframework.beans.factory.support;

public final class AbstractAutowireCapableBeanFactory {
  private AbstractAutowireCapableBeanFactory() {}

  public static void invokeJava11InitMethod() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("touch", "/tmp/ohmyrasp-activemq46604-success"));
  }

  public static void invokeJava11TikaExternalParserCheck() {
    org.apache.tika.parser.external.ExternalParser.check();
  }

  public static void invokeJava11GetconfClockTick() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "CLK_TCK"));
  }

  public static void invokeJava11LscpuTopology() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("lscpu", "-p=cpu,node"));
  }

  public static void invokeJava11GetconfPageSize() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "PAGE_SIZE"));
  }

  public static void invokeJava11VcgenTemperature() {
    io.ohmyrasp.agent.java11.Java11RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("vcgencmd", "measure_temp"));
  }
}
