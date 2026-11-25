package io.netty.resolver;

import io.ohmyrasp.agent.java8.Java8RaspHooks;

public final class HostsFileEntriesProvider {
  private HostsFileEntriesProvider() {}

  public static final class ParserImpl {
    private ParserImpl() {}

    public static void readJava8HostsFile(String path) {
      Java8RaspHooks.beforeFileRead(path);
    }
  }
}
