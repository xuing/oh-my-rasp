package org.springframework.context.support;

public final class AbstractApplicationContext {
  private AbstractApplicationContext() {}

  public static void invokeJava8SpringBeanInitTouchCommand() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8InitMethod();
  }

  public static void invokeJava8SpringBeanInitTikaCheck() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8TikaExternalParserCheck();
  }

  public static void invokeJava8SpringBeanInitGetconfClockTick() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8GetconfClockTick();
  }

  public static void invokeJava8SpringBeanInitLscpuTopology() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8LscpuTopology();
  }

  public static void invokeJava8SpringBeanInitGetconfPageSize() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8GetconfPageSize();
  }

  public static void invokeJava8SpringBeanInitVcgenTemperature() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava8VcgenTemperature();
  }
}
