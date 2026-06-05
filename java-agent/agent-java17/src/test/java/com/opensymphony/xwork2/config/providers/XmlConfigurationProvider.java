package com.opensymphony.xwork2.config.providers;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class XmlConfigurationProvider {
  private XmlConfigurationProvider() {}

  public static void parseLocalEntity(String name, String systemId) {
    Java17RaspHooks.beforeXmlEntity(name, systemId);
  }
}
