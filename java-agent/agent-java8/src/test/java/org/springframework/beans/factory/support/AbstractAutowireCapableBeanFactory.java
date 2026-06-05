package org.springframework.beans.factory.support;

public final class AbstractAutowireCapableBeanFactory {
  private AbstractAutowireCapableBeanFactory() {}

  public static void invokeJava8InitMethod() {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("touch", "/tmp/ohmyrasp-activemq46604-success"));
  }

  public static void invokeJava8TikaExternalParserCheck() {
    org.apache.tika.parser.external.ExternalParser.check();
  }

  public static void invokeJava8GetconfClockTick() {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "CLK_TCK"));
  }

  public static void invokeJava8LscpuTopology() {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("lscpu", "-p=cpu,node"));
  }

  public static void invokeJava8GetconfPageSize() {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("getconf", "PAGE_SIZE"));
  }

  public static void invokeJava8VcgenTemperature() {
    io.ohmyrasp.agent.java8.Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("vcgencmd", "measure_temp"));
  }
}
