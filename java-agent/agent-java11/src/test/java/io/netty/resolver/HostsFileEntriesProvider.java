package io.netty.resolver;

import io.ohmyrasp.agent.java11.Java11RaspHooks;

public final class HostsFileEntriesProvider {
  private HostsFileEntriesProvider() {}

  public static final class ParserImpl {
    private ParserImpl() {}

    public static void readJava11HostsFile(String path) {
      Java11RaspHooks.beforeFileRead(path);
    }
  }
}
