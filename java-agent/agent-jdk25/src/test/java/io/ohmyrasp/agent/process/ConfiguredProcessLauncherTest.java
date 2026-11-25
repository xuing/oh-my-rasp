package io.ohmyrasp.agent.process;

import io.ohmyrasp.agent.rules.product.rocketmq.RocketMqFilterServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ConfiguredProcessLauncherTest {
  @Test
  void requiresTheLauncherToBeTheDirectCallerOfTheProcessApi() {
    var start = frame("java.lang.ProcessBuilder", "start");
    var exec = frame("java.lang.Runtime", "exec");
    var launcher = frame("org.apache.rocketmq.broker.filtersrv.FilterServerUtil", "callShell");
    var owner = frame("org.apache.rocketmq.broker.filtersrv.FilterServerManager", "run");
    var worker = frame("app.ExportJob", "run");
    assertTrue(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{start, exec, exec, launcher, owner}));
    assertFalse(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{start, worker, launcher, owner}));
    assertTrue(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{exec, owner}));
    assertFalse(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{exec, launcher, worker}));
    assertFalse(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{exec, launcher, worker, owner}));
    assertFalse(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{worker, launcher, owner}));
    assertFalse(RocketMqFilterServer.directlyCallsProcessApi(new StackTraceElement[]{start}));
    assertEquals(owner.getClassName(), RocketMqFilterServer.directOwner(
        List.of(start.getClassName(), launcher.getClassName(), owner.getClassName())));
    assertNull(RocketMqFilterServer.directOwner(
        List.of(start.getClassName(), launcher.getClassName() + "Metrics", owner.getClassName())));
  }

  @Test
  void distinguishesIdenticalProgramsByObservedLaunchContext() {
    var script = PosixShellCommand.from(List.of("sh", "-c", "printf data | cat", "_", "item"));
    var fixedCommand = PosixShellCommand.from(List.of("sh", "-c", "printf data"));
    var exec = frame("java.lang.Runtime", "exec");
    var owner = frame("org.apache.rocketmq.broker.filtersrv.FilterServerManager", "run");
    var helper = frame("org.apache.rocketmq.broker.filtersrv.FilterServerUtil", "callShell");
    var ordinary = new StackTraceElement[]{exec, frame("app.Report", "run")};
    var configured = new StackTraceElement[]{exec, helper, owner};
    assertNull(ShellControlSource.classify(script, null, ordinary));
    assertNull(ShellControlSource.classify(script, List.of("item"), ordinary));
    assertEquals(ShellControlSource.REQUEST, ShellControlSource.classify(script, List.of("data | cat"), ordinary));
    assertEquals(ShellControlSource.CONFIGURATION, ShellControlSource.classify(script, null, configured));
    assertNull(ShellControlSource.classify(fixedCommand, null, configured));
  }

  private static StackTraceElement frame(String owner, String method) {
    return new StackTraceElement(owner, method, null, -1);
  }
}
