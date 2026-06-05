package com.opensymphony.xwork2.config.providers;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class XmlConfigurationProvider {
  private XmlConfigurationProvider() {}

  public static void parseLocalEntity(String name, String systemId) {
    Java11RaspHooks.beforeXmlEntity(name, systemId);
  }
}
