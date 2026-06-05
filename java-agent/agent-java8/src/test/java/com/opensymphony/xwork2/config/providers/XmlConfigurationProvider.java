package com.opensymphony.xwork2.config.providers;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class XmlConfigurationProvider {
  private XmlConfigurationProvider() {}

  public static void parseLocalEntity(String name, String systemId) {
    Java8RaspHooks.beforeXmlEntity(name, systemId);
  }
}
