package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** NetworkDestinationDetector: Outbound URLs, HTTP transports, XML attachment references, DNS names and XML entity system IDs. */
final class NetworkDestinationDetectorTest {
  @ParameterizedTest
  @ValueSource(strings = {
      "http://metadata.google.internal./", "http://[fd00:ec2:0:0:0:0:0:254]/",
      "http://100.100.100.200/", "http://[::ffff:169.254.169.254]/"
  })
  void recognizesMetadataDestination(String target) {
    assertAlgorithm(NetworkDestinationDetector.detectUrl(target, request()), "ssrf_aws");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "http://[::1]/asset", "http://[fd01::7]/asset", "http://[fe80::42]/asset",
      "http://[::ffff:192.168.1.2]/asset"
  })
  void recognizesInternalXmlAttachmentDestination(String target) {
    assertAlgorithm(NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", target, request()), "ssrf_userinput");
  }

  @Test
  void recognizesFullyQualifiedCallbackDomain() {
    assertAlgorithm(NetworkDestinationDetector.detectDns("Test.Dnslog.Cn.", request()), "dns_blacklist");
  }

  @Test
  void distinguishesConfiguredScopedAddressFromCopiedServiceUrl() {
    assertTrue(NetworkDestinationDetector.detectUrl("http://[fe80::42%25eth0]/health", request()).isEmpty());
    String service = "http://inventory_api/records";
    assertTrue(NetworkDestinationDetector.detectUrl(service, request(Map.of("url", List.of(service)))).isEmpty());
    assertAlgorithm(NetworkDestinationDetector.detectUrl(service, request(Map.of("url", List.of(service))), true), "ssrf_userinput");
  }

  @Test
  void comparesSuppliedUrlAuthorityAndPath() {
    var ctx = request(Map.of("endpoint", List.of("https://10.1.2.3:443/files")));
    assertAlgorithm(NetworkDestinationDetector.detectUrl("https://10.1.2.3/files/42", ctx), "ssrf_userinput");
    assertTrue(NetworkDestinationDetector.detectUrl("https://10.1.2.3/fileset/42", ctx).isEmpty());
    assertTrue(NetworkDestinationDetector.detectUrl("https://10.1.2.3:8443/files/42", ctx).isEmpty());
    assertTrue(NetworkDestinationDetector.detectUrl("https://media.example.test/files/42", ctx).isEmpty());
  }

  @Test
  void detectsSsrfAwsMetadata() {
    var result = NetworkDestinationDetector.detectUrl("http://169.254.169.254/latest/meta-data/", request());

    assertTrue(result.isPresent());
    assertEquals("ssrf_aws", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSsrfUserInput() {
    var result =
        NetworkDestinationDetector.detectUrl(
            "http://127.0.0.1/admin",
            request(Map.of("url", List.of("http://127.0.0.1/admin"))));

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void detectsGeoServerCve202140822TestWfsPostExternalSsrfRelay() {
    String target = "http://interal/geoserver/../";
    var context =
        new RequestContext(
            "POST",
            "/geoserver/TestWfsPost",
            "url=http%3A%2F%2Finteral%2Fgeoserver%2F..%2F&body=testtest",
            Map.of(
                "url",
                List.of(target),
                "body",
                List.of("testtest"),
                "username",
                List.of("admin"),
                "password",
                List.of("admin")),
            Map.of("user-agent", "JUnit", "host", "interal"));

    assertTrue(NetworkDestinationDetector.detectUrl(target, context).isEmpty());
    var result = NetworkDestinationDetector.detectUrl(target, context, true);

    assertAlgorithm(result, "ssrf_userinput");
    assertTrue(result.orElseThrow().requiresExplicitRule());
    assertEquals("interal", result.orElseThrow().details().get("host"));
    assertEquals(target, result.orElseThrow().details().get("url"));
  }

  @Test
  void detectsWebLogicUddiExplorerOperatorSsrfRelay() {
    String target =
        "http://172.19.0.2:6379/test%0D%0A%0D%0Aconfig%20set%20dir%20/etc/%0D%0Asave";
    var context =
        new RequestContext(
            "GET",
            "/uddiexplorer/SearchPublicRegistries.jsp",
            "rdoSearch=name&txtSearchname=sdf&selfor=Business+location&operator="
                + "http%3A%2F%2F172.19.0.2%3A6379%2Ftest%250D%250A%250D%250Aconfig%2520set%2520dir%2520%2Fetc%2F%250D%250Asave",
            Map.of(
                "rdoSearch",
                List.of("name"),
                "txtSearchname",
                List.of("sdf"),
                "selfor",
                List.of("Business location"),
                "operator",
                List.of(target)),
            Map.of("user-agent", "JUnit"));

    var result = NetworkDestinationDetector.detectUrl(target, context);

    assertAlgorithm(result, "ssrf_userinput");
    assertEquals("172.19.0.2", result.orElseThrow().details().get("host"));
    assertEquals(target, result.orElseThrow().details().get("url"));
  }

  @Test
  void ignoresPublicExternalUrlWithoutRequestControl() {
    var result = NetworkDestinationDetector.detectUrl("https://example.com/public.xml", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfProtocol() {
    var result = NetworkDestinationDetector.detectUrl("gopher://127.0.0.1:6379/_info", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopFileAttachmentReference() {
    var result = NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
    assertEquals("cxf-aegis-xop", result.orElseThrow().details().get("mechanism"));
  }

  @Test
  void detectsCxfXopCidWrappedFileAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "cid:file:///etc/hosts", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void detectsCxfXopInternalHttpAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("cxf-aegis-xop", "http://127.0.0.1/admin", request());

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void ignoresPublicCxfXopHttpAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference(
            "cxf-aegis-xop", "https://example.com/public-image.png", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownXmlAttachmentMechanism() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference("mail-url-datasource", "file:///etc/hosts", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundCxfXopAttachmentReference() {
    var result =
        NetworkDestinationDetector.detectXmlAttachmentReference(
            "cxf-aegis-xop", "file:///etc/hosts", RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresLocalClasspathJarResource() {
    var result =
        NetworkDestinationDetector.detectUrl(
            "jar:file:/usr/local/tomcat/lib/servlet-api.jar!/jakarta/servlet/LocalStrings.properties",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSpringBootNestedClasspathResource() {
    var result =
        NetworkDestinationDetector.detectUrl(
            "jar:nested:/app.jar/!BOOT-INF/lib/fastjson-1.2.83.jar!/com/alibaba/fastjson/parser/ParserConfig.class",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void distinguishesArchiveConfigurationFromRequestSelection() {
    String archive = "https://reports.invalid/releases/weekly.jar";
    String entry = "jar:" + archive + "!/summary.txt";
    assertTrue(NetworkDestinationDetector.detectUrl(entry, request()).isEmpty());
    var configured = NetworkDestinationDetector.detectUrl(entry, request(), true).orElseThrow();
    assertTrue(configured.requiresExplicitRule());
    for (String selected : List.of(archive, entry)) {
      var input = request(Map.of("archive", List.of(selected)));
      assertTrue(NetworkDestinationDetector.detectUrl(entry, input).isEmpty());
      assertTrue(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(archive), archive, "reports.invalid", input));
      String other = "https://reports.invalid/releases/other.jar";
      assertFalse(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(other), other, "reports.invalid", input));
    }
    var json = new RequestContext("POST", "/reports", "", Map.of(), Map.of("content-type", "application/json"),
        "{\"archive\":\"" + entry + "\"}");
    assertTrue(NetworkDestinationDetector.requestSuppliesHttpUrl(java.net.URI.create(archive), archive, "reports.invalid", json));
    var broad = io.ohmyrasp.agent.policy.AgentPolicy.parse("{\"rules\":[{\"hook\":\"ssrf\",\"action\":\"block\"}]}");
    var explicit = io.ohmyrasp.agent.policy.AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"ssrf_protocol\",\"action\":\"block\"}]}");
    assertTrue(broad.evaluate(configured, "").ignored());
    assertEquals("block", explicit.evaluate(configured, "").detection().action());
  }

  @Test
  void ignoresTomcatLibraryFileResource() {
    var result = NetworkDestinationDetector.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void checksWhoSelectedALocalFileUrl() {
    String appFile = "file:/srv/orders/lib/renderer.jar";
    assertTrue(NetworkDestinationDetector.detectUrl(appFile, request()).isEmpty());
    assertAlgorithm(NetworkDestinationDetector.detectUrl(appFile, request(Map.of("source", List.of("file:///srv/orders/lib/")))),
        "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar",
        request(Map.of("source", List.of("/usr/local/tomcat/lib/servlet-api.jar")))), "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file://host.example.invalid/share/readme", request()), "ssrf_protocol");
    assertAlgorithm(NetworkDestinationDetector.detectUrl("file:/etc/shadow", request()), "ssrf_protocol");
  }

  @Test
  void detectsSsrfCommonCallbackDomain() {
    var result = NetworkDestinationDetector.detectUrl("http://probe.dnslog.cn/callback", request());

    assertAlgorithm(result, "ssrf_common");
  }

  @Test
  void detectsSsrfObfuscatedHost() {
    var result = NetworkDestinationDetector.detectUrl("http://2130706433/", request());

    assertAlgorithm(result, "ssrf_obfuscate");
  }

  @Test
  void detectsDnslogHost() {
    var result = NetworkDestinationDetector.detectDns("abc.dnslog.cn", request());

    assertTrue(result.isPresent());
    assertEquals("dns_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsXxeProtocol() {
    var result = NetworkDestinationDetector.detectXxeEntity("xxe", "file:///etc/passwd", request());

    assertTrue(result.isPresent());
    assertEquals("xxe_protocol", result.orElseThrow().algorithm());
  }
}
