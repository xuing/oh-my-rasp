package org.springframework.context.support;

public final class AbstractApplicationContext {
  private AbstractApplicationContext() {}

  public static void invokeJava17SpringBeanInitTouchCommand() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17InitMethod();
  }

  public static void invokeJava17SpringBeanInitTikaCheck() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17TikaExternalParserCheck();
  }

  public static void invokeJava17SpringBeanInitGetconfClockTick() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17GetconfClockTick();
  }

  public static void invokeJava17SpringBeanInitLscpuTopology() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17LscpuTopology();
  }

  public static void invokeJava17SpringBeanInitGetconfPageSize() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17GetconfPageSize();
  }

  public static void invokeJava17SpringBeanInitVcgenTemperature() {
    org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory
        .invokeJava17VcgenTemperature();
  }
}
