package io.dataease.xpack.permissions.apisix.manage;

import io.ohmyrasp.agent.java8.Java8RaspHooks;
import java.net.URL;
import org.springframework.boot.SpringApplicationRunListeners;

public final class XpackRouteManage {
  private XpackRouteManage() {}

  public static void checkApisixUpstreams() throws Exception {
    SpringApplicationRunListeners.ready(
        () -> Java8RaspHooks.beforeUrlOpen(new URL("http://127.0.0.1:9180/apisix/admin/upstreams")));
  }
}
