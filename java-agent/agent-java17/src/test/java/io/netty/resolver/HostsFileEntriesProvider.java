package io.netty.resolver;

import io.ohmyrasp.agent.java17.Java17RaspHooks;

public final class HostsFileEntriesProvider {
  private HostsFileEntriesProvider() {}

  public static final class ParserImpl {
    private ParserImpl() {}

    public static void readJava17HostsFile(String path) {
      Java17RaspHooks.beforeFileRead(path);
    }
  }
}
