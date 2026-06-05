package org.springframework.context.support;

public final class AbstractApplicationContext {
  private AbstractApplicationContext() {}

  public static void invokeJava11SpringBeanInitTouchCommand() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11InitMethod();
  }

  public static void invokeJava11SpringBeanInitTikaCheck() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11TikaExternalParserCheck();
  }

  public static void invokeJava11SpringBeanInitGetconfClockTick() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11GetconfClockTick();
  }

  public static void invokeJava11SpringBeanInitLscpuTopology() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11LscpuTopology();
  }

  public static void invokeJava11SpringBeanInitGetconfPageSize() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11GetconfPageSize();
  }

  public static void invokeJava11SpringBeanInitVcgenTemperature() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava11VcgenTemperature();
  }
}
