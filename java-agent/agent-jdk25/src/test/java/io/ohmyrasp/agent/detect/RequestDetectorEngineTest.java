package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.jsonString;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Request routing, credentials, upload and resource rules. */
final class RequestDetectorEngineTest {
  private final DetectorEngine engine = new DetectorEngine();

  @Test
  void detectsScannerRequest() {
    var context =
        new RequestContext(
            "GET", "/rasp/request", "", Map.of(), Map.of("user-agent", "sqlmap/1.7"));

    assertTrue(engine.detectRequest(context).isEmpty());
    var result = engine.detectScannerUserAgent(context);

    assertTrue(result.isPresent());
    assertEquals("request_scanner", result.orElseThrow().algorithm());
  }

  @Test
  void acceptsOrdinaryRequestWithoutUserAgent() {
    var context = new RequestContext("GET", "/rasp/request", "", Map.of(), Map.of());

    var result = engine.detectRequest(context);

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsInternalServiceIdentityOnSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/auth/users",
            "pageNo=1&pageSize=9",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_identity");
  }

  @Test
  void detectsNacosCve202129441CreateUserInternalIdentityBypass() {
    var context =
        new RequestContext(
            "POST",
            "/nacos/v1/auth/users",
            "username=vulhub&password=vulhub",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_identity");
  }

  @Test
  void ignoresInternalServiceIdentityOnNonControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/ns/instance/list",
            "",
            Map.of(),
            Map.of("user-agent", "Nacos-Server"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNormalUserAgentOnSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/nacos/v1/auth/users",
            "",
            Map.of(),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJwtSignedWithKnownDefaultSecret() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "authorization",
                "Bearer "
                    + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
                    + "mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_jwt_secret");
    assertEquals("hugegraph-default-token-secret", result.orElseThrow().details().get("keyId"));
  }

  @Test
  void ignoresJwtWithMismatchedDefaultSecretSignature() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "authorization",
                "Bearer "
                    + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                    + "eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9."
                    + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresMalformedBearerJwt() {
    var context =
        new RequestContext(
            "GET",
            "/graphs",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", "Bearer not-a-jwt"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRememberMeCookieEncryptedWithKnownDefaultKey() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "sid=abc; rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8=; theme=light"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_crypto_cookie");
    assertEquals("rememberMe", result.orElseThrow().details().get("cookieName"));
    assertEquals("shiro-default-aes-key", result.orElseThrow().details().get("keyId"));
  }

  @Test
  void detectsShiroCve20164437RootRememberMeCookie() {
    var context =
        new RequestContext(
            "GET",
            "/",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8="));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_crypto_cookie");
    assertEquals("/", result.orElseThrow().details().get("uri"));
    assertEquals("GET", result.orElseThrow().details().get("method"));
  }

  @Test
  void ignoresRememberMeCookieWithInvalidCiphertext() {
    var context =
        new RequestContext(
            "GET",
            "/login",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "cookie",
                "rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3CAA"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsfViewStateValue() {
    var context =
        new RequestContext(
            "POST",
            "/index.xhtml",
            "",
            Map.of("javax.faces.ViewState", List.of("1234567890abcdef")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsBasicAuthKnownDefaultCredentialOnManagementPath() {
    var context =
        new RequestContext(
            "GET",
            "/manager/html",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", basic("tomcat", "tomcat")));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_credential");
    assertEquals("tomcat-manager-default", result.orElseThrow().details().get("credentialId"));
    assertEquals("basic", result.orElseThrow().details().get("mechanism"));
    assertEquals("tomcat", result.orElseThrow().details().get("username"));
    assertEquals("Basic [redacted]", result.orElseThrow().request().headers().get("authorization"));
  }

  @Test
  void detectsFormKnownDefaultCredentialOnConsolePath() {
    var context =
        new RequestContext(
            "POST",
            "/console/j_security_check",
            "j_username=weblogic&j_password=Oracle%40123",
            Map.of("j_username", List.of("weblogic"), "j_password", List.of("Oracle@123")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_default_credential");
    assertEquals("weblogic-lab-default", result.orElseThrow().details().get("credentialId"));
    assertEquals("form", result.orElseThrow().details().get("mechanism"));
    assertEquals("j_username", result.orElseThrow().details().get("usernameSource"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("j_password").get(0));
    assertEquals("j_username=weblogic&j_password=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresKnownDefaultCredentialOutsideControlPath() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "",
            Map.of("username", List.of("admin"), "password", List.of("admin")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNonDefaultCredentialOnControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/admin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "authorization", basic("admin", "strong-password")));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsEmptyCredentialAuthBypassOnControlEndpoint() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/ProgramExport/",
            "USERNAME=&PASSWORD=&requirePasswordChange=Y",
            Map.of(
                "USERNAME", List.of(""),
                "PASSWORD", List.of(""),
                "requirePasswordChange", List.of("Y")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_empty_credential_bypass");
    assertEquals("USERNAME", result.orElseThrow().details().get("usernameParameter"));
    assertEquals("PASSWORD", result.orElseThrow().details().get("passwordParameter"));
    assertEquals("requirePasswordChange", result.orElseThrow().details().get("bypassParameter"));
  }

  @Test
  void ignoresEmptyCredentialsOnOrdinaryLoginEndpoint() {
    var context =
        new RequestContext(
            "POST",
            "/login",
            "USERNAME=&PASSWORD=&requirePasswordChange=Y",
            Map.of(
                "USERNAME", List.of(""),
                "PASSWORD", List.of(""),
                "requirePasswordChange", List.of("Y")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresControlEndpointEmptyCredentialsWithoutBypassFlag() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/ProgramExport/",
            "USERNAME=&PASSWORD=",
            Map.of("USERNAME", List.of(""), "PASSWORD", List.of("")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsConfluenceSetupCompletionStateReset() {
    var context =
        new RequestContext(
            "GET",
            "/server-info.action",
            "bootstrapStatusProvider.applicationConfig.setupComplete=false",
            Map.of("bootstrapStatusProvider.applicationConfig.setupComplete", List.of("false")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_setup_state_reset");
    assertEquals(
        "bootstrapStatusProvider.applicationConfig.setupComplete",
        result.orElseThrow().details().get("parameter"));
    assertEquals("false", result.orElseThrow().details().get("value"));
  }

  @Test
  void detectsBracketedSetupCompletionStateReset() {
    var context =
        new RequestContext(
            "GET",
            "/setup/setupadministrator.action",
            "bootstrapStatusProvider[applicationConfig][setupComplete]=0",
            Map.of("bootstrapStatusProvider[applicationConfig][setupComplete]", List.of("0")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_setup_state_reset");
    assertEquals("0", result.orElseThrow().details().get("value"));
  }

  @Test
  void ignoresSetupCompletionWhenNotReset() {
    var context =
        new RequestContext(
            "GET",
            "/server-info.action",
            "bootstrapStatusProvider.applicationConfig.setupComplete=true",
            Map.of("bootstrapStatusProvider.applicationConfig.setupComplete", List.of("true")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOrdinaryNestedSetupCompleteState() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "project.setupComplete=false",
            Map.of("project.setupComplete", List.of("false")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresPutToStaticAssetPath() {
    var context =
        new RequestContext(
            "PUT", "/assets/upload/report.txt", "", Map.of(), Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsMultipartUploadFilenameOverrideTraversal() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "fileFileName=..%2Fshell.jsp",
            Map.of("fileFileName", List.of("../shell.jsp")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_upload_filename_override");
    assertEquals("fileFileName", result.orElseThrow().details().get("parameter"));
    assertEquals("traversal", result.orElseThrow().details().get("targetType"));
    assertEquals("12", result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("fileFileName"));
    assertTrue(result.orElseThrow().request().query().contains("fileFileName=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("shell.jsp"));
  }

  @Test
  void ignoresSafeMultipartUploadFilenameMetadata() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "fileFileName=reports%2Fsummary.txt",
            Map.of("fileFileName", List.of("reports/summary.txt")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresUploadFilenameOverrideOutsideMultipartContext() {
    var context =
        new RequestContext(
            "POST",
            "/profile",
            "fileFileName=..%2Fshell.jsp",
            Map.of("fileFileName", List.of("../shell.jsp")),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTeamCityDebugProcessLaunchParameter() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/debug/processes",
            "exePath=id",
            Map.of("exePath", List.of("id")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_debug_process_launch");
    assertEquals("exePath", result.orElseThrow().details().get("parameter"));
    assertEquals("2", result.orElseThrow().details().get("commandLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("exePath"));
    assertEquals("exePath=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresDebugProcessesRequestWithoutExecutableParameter() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/debug/processes",
            "locator=all",
            Map.of("locator", List.of("all")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresExecutableParameterOutsideDebugProcessContext() {
    var context =
        new RequestContext(
            "POST",
            "/app/rest/builds",
            "exePath=id",
            Map.of("exePath", List.of("id")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresMetabaseInitJsonOutsideSetupValidationPath() {
    var init =
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec('touch /tmp/success')\n$$";
    var body =
        """
        {"init":"%s"}
        """
            .formatted(jsonString(init).replace("\n", "\\n"));
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignH2ConsoleJdbcUrl() {
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=jdbc%3Ah2%3Amem%3Atest",
            Map.of("driver", List.of("org.h2.Driver"), "url", List.of("jdbc:h2:mem:test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignWebLogicConsoleHandle() {
    var handle = "com.example.console.HelpPage(\"welcome\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignDataEaseBase64H2DatasourceConfig() {
    var configuration =
        "{\"jdbc\":\"jdbc:h2:mem:pwn;MODE=MSSQLServer\",\"username\":\"\",\"password\":\"\","
            + "\"driver\":\"org.h2.Driver\"}";
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var body = "{\"name\":\"p1\",\"type\":\"h2\",\"configuration\":\"" + encoded + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/de2api/datasource/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignUnomiContextJsonBody() {
    var body =
        """
        {
          "filters": [{
            "id": "sample",
            "filters": [{
              "condition": {
                "parameterValues": {
                  "propertyName": "profile.gender",
                  "comparisonOperator": "equals",
                  "propertyValue": "male"
                },
                "type": "profilePropertyCondition"
              }
            }]
          }],
          "sessionId": "sample"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRuntimeTextInJsonBodyOutsideDynamicConfigShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"message\":\"java.lang.Runtime.getRuntime().exec('id')\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignLookupAndRawLdapText() {
    var context =
        new RequestContext(
            "GET",
            "/solr/admin/cores",
            "action=${date:yyyy}&next=ldap://example.com/a",
            Map.of(
                "action",
                List.of("${date:yyyy}"),
                "next",
                List.of("ldap://example.com/a")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRawLdapUrlWithOrdinaryJdbcDriver() {
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=ldap%3A%2F%2Fexample.com%2Fnot-jndi",
            Map.of(
                "driver",
                List.of("org.h2.Driver"),
                "url",
                List.of("ldap://example.com/not-jndi")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsGeoServerCve202325157OgcCqlFilterSqlInjection() {
    var filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";
    var encodedFilter =
        "strStartsWith%28name%2C%27x%27%27%29+%3D+true+and+1%3D%28SELECT+CAST+%28%28SELECT+version%28%29%29+AS+integer%29%29+--+%27%29+%3D+true";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/ows",
            "service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER="
                + encodedFilter,
            Map.of(
                "service",
                List.of("wfs"),
                "version",
                List.of("1.0.0"),
                "request",
                List.of("GetFeature"),
                "typeName",
                List.of("vulhub:example"),
                "CQL_FILTER",
                List.of(filter)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_ogc_filter_sql_injection");
    assertEquals("CQL_FILTER", result.orElseThrow().details().get("parameter"));
    assertEquals(String.valueOf(filter.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("CQL_FILTER"));
    assertTrue(result.orElseThrow().request().query().contains("CQL_FILTER=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("SELECT"));
  }

  @Test
  void ignoresBenignGeoserverOgcCqlFilter() {
    var filter = "strStartsWith(name,'x') = true and population > 10";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/ows",
            "service=wfs&request=GetFeature&CQL_FILTER=strStartsWith%28name%2C%27x%27%29",
            Map.of(
                "service",
                List.of("wfs"),
                "request",
                List.of("GetFeature"),
                "CQL_FILTER",
                List.of(filter)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOgcCqlFilterSqlInjectionOutsideOgcContext() {
    var filter =
        "strStartsWith(name,'x'') = true and 1=(SELECT CAST ((SELECT version()) AS integer))"
            + " -- ') = true";
    var context =
        new RequestContext(
            "GET",
            "/api/search",
            "CQL_FILTER=1",
            Map.of("CQL_FILTER", List.of(filter)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignSpringBindingParameterName() {
    var context =
        new RequestContext(
            "POST",
            "/hotels/booking",
            "_%28new%20java.lang.String%28%22guest%22%29%29.toString%28%29=vulhub",
            Map.of("_(new java.lang.String(\"guest\")).toString()", List.of("vulhub")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignXmlPayloadClassMetadata() {
    var payload =
        """
        <map>
          <entry>
            <string>profile</string>
            <value class="java.util.LinkedHashMap">
              <entry><string>name</string><string>vulhub</string></entry>
            </value>
          </entry>
        </map>
        """;
    var context =
        new RequestContext(
            "POST",
            "/orders/3/edit",
            "",
            Map.of(),
            Map.of("content-type", "application/xml", "user-agent", "JUnit"),
            payload);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignInternalDoctype() {
    var xml =
        "%3C!DOCTYPE%20note%20%5B%3C!ENTITY%20writer%20%22Alice%22%3E%5D%3E"
            + "%3Cnote%3E%26writer%3B%3C/note%3E";
    var context =
        new RequestContext(
            "POST",
            "/xml/preview",
            "",
            Map.of("xml", List.of(xml)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRuntimeWordsInPlainContactMessage() {
    var message = "Please review why java.lang.Runtime.getRuntime().exec appears in this log.";
    var context =
        new RequestContext(
            "POST",
            "/secure/ContactAdministrators!default.jspa",
            "",
            Map.of("details", List.of(message)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrRemoteStreamingParameterConfigEnable() {
    var config =
        """
        {"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of("config", List.of(config)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("enable-config", result.orElseThrow().details().get("mode"));
    assertEquals("config", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-streaming", result.orElseThrow().details().get("scheme"));
  }

  @Test
  void detectsSolrRemoteStreamingJsonBodyConfigEnable() {
    var body =
        """
        {"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("enable-config", result.orElseThrow().details().get("mode"));
    assertEquals("body", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-streaming", result.orElseThrow().details().get("scheme"));
  }

  @Test
  void detectsSolrRemoteStreamingFileUrl() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/debug/dump",
            "stream.url=file:///etc/passwd",
            Map.of("stream.url", List.of("file:///etc/passwd")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_content_stream");
    assertEquals("stream-url", result.orElseThrow().details().get("mode"));
    assertEquals("stream.url", result.orElseThrow().details().get("parameter"));
    assertEquals("file", result.orElseThrow().details().get("scheme"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("stream.url").get(0));
    assertEquals("stream.url=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresExternalRemoteContentStreamUrl() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/debug/dump",
            "stream.url=https://example.com/feed.xml",
            Map.of("stream.url", List.of("https://example.com/feed.xml")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRemoteImportIntoDataFileTarget() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/viewdatafile",
            "",
            Map.of(
                "DATAFILE_LOCATION",
                List.of("http://example.com/report.csv"),
                "DATAFILE_SAVE",
                List.of("./runtime/uploads/report.csv"),
                "DATAFILE_IS_URL",
                List.of("true")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsElasticsearchWooYun2015110216SnapshotRepositoryWebrootWrite() {
    var location = "/usr/local/tomcat/webapps/wwwroot/";
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\""
            + location
            + "\",\"compress\":false}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/yz.jsp",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_repository_webroot_write");
    assertEquals("body.location", result.orElseThrow().details().get("targetParameter"));
    assertEquals("jsp", result.orElseThrow().details().get("targetType"));
    assertEquals("webroot", result.orElseThrow().details().get("locationType"));
    assertEquals(
        String.valueOf(location.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresElasticsearchSnapshotRepositoryUnderConfiguredRepo() {
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/share/elasticsearch/repo/test\"}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/test",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsOpenTsdbCve202035476YrangePlotCommandInjection() {
    var payload = "[0:system('touch /tmp/success')]";
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:system(%27touch%20/tmp/success%27)]&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "yrange",
                List.of(payload),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_plot_command_injection");
    assertEquals("yrange", result.orElseThrow().details().get("parameter"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("yrange"));
    assertTrue(result.orElseThrow().request().query().contains("yrange=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("system"));
  }

  @Test
  void detectsOpenTsdbCve202325826KeyPlotCommandInjection() {
    var payload = ";system \"touch /tmp/poc\" \"";
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&y2range=[42:42]&key=%3Bsystem%20%22touch%20/tmp/poc%22%20%22&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "y2range",
                List.of("[42:42]"),
                "key",
                List.of(payload),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_plot_command_injection");
    assertEquals("key", result.orElseThrow().details().get("parameter"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("key"));
    assertTrue(result.orElseThrow().request().query().contains("key=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("touch"));
  }

  @Test
  void ignoresBenignPlotRangeParameters() {
    var context =
        new RequestContext(
            "GET",
            "/q",
            "start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&yrange=[0:100]&key=out%20right%20top&wxh=1516x644&style=linespoint&grid=t&json",
            Map.of(
                "start",
                List.of("2000/10/21-00:00:00"),
                "m",
                List.of("sum:sys.cpu.nice"),
                "yrange",
                List.of("[0:100]"),
                "key",
                List.of("out right top"),
                "wxh",
                List.of("1516x644"),
                "style",
                List.of("linespoint"),
                "grid",
                List.of("t"),
                "json",
                List.of("")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresPlotCommandValueOutsideGraphContext() {
    var context =
        new RequestContext(
            "GET",
            "/settings",
            "key=%3Bsystem%20%22touch%20/tmp/poc%22%20%22&mode=test",
            Map.of("key", List.of(";system \"touch /tmp/poc\" \""), "mode", List.of("test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJsonSortSqlInjection() {
    var payload = ",if(1=1,sleep(2),0)";
    var body =
        """
        {"orders":[{"name":"name","type":"%s"}],"components":[],"filters":{}}
        """
            .formatted(payload);
    var context =
        new RequestContext(
            "POST",
            "/test/case/list/1/10",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
    var result = SqlRequestIndicators.sqlRequestMetadata(context, "request_sql_sort_injection"::equals).stream().findFirst();

    assertAlgorithm(result, "request_sql_sort_injection");
    assertEquals("type", result.orElseThrow().details().get("field"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsSkyWalkingGraphqlSqlIdentifierInjection() {
    var payload = "sqli where 1=1 --";
    var body =
        """
        {
          "query":"query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) { total } }",
          "variables":{"condition":{"metricName":"%s","state":"ALL","paging":{"pageSize":10}}}
        }
        """
            .formatted(payload);
    var context =
        new RequestContext(
            "POST",
            "/graphql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
    var result = SqlRequestIndicators.sqlRequestMetadata(context, "request_sql_identifier_injection"::equals).stream().findFirst();

    assertAlgorithm(result, "request_sql_identifier_injection");
    assertEquals("metricName", result.orElseThrow().details().get("field"));
    assertEquals(String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignGraphqlMetricIdentifier() {
    var body =
        """
        {
          "query":"query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) { total } }",
          "variables":{"condition":{"metricName":"service_instance_jvm_memory.max","state":"ALL"}}
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/graphql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsonSortDirection() {
    var body =
        """
        {"orders":[{"name":"name","type":"asc"}],"components":[],"filters":{}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/test/case/list/1/10",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresSqlLikeTypeOutsideSortContext() {
    var body =
        """
        {"type":",if(1=1,sleep(2),0)","message":"diagnostic"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignGatewayRouteConfig() {
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/report",
            "",
            Map.of(
                "routeConfig",
                List.of(
                    "{\"filters\":[{\"name\":\"AddResponseHeader\",\"args\":{\"value\":\"ok\"}}],\"uri\":\"http://example.com\"}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsInternalForwardToSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=/app/rest/users;.jsp",
            Map.of("jsp", List.of("/app/rest/users;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_forward");
    assertEquals("jsp", result.orElseThrow().details().get("parameter"));
  }

  @Test
  void detectsEncodedInternalForwardToSensitiveControlPath() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=%2Fapp%2Frest%2Fusers%3B.jsp",
            Map.of("jsp", List.of("%2Fapp%2Frest%2Fusers%3B.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_internal_forward");
  }

  @Test
  void ignoresInternalForwardWithoutServletSuffixConfusion() {
    var context =
        new RequestContext(
            "GET",
            "/hax",
            "jsp=/app/rest/users",
            Map.of("jsp", List.of("/app/rest/users")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresOrdinaryInternalJspForward() {
    var context =
        new RequestContext(
            "GET",
            "/dashboard",
            "jsp=/WEB-INF/jsp/help;.jsp",
            Map.of("jsp", List.of("/WEB-INF/jsp/help;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresSensitiveForwardTargetInNonForwardParameter() {
    var context =
        new RequestContext(
            "GET",
            "/search",
            "q=/app/rest/users;.jsp",
            Map.of("q", List.of("/app/rest/users;.jsp")),
            Map.of("user-agent", "Mozilla/5.0"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsXssRequestInput() {
    var result = engine.detectMarkupParameter(request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertTrue(result.isPresent());
    assertEquals("xss_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsXssRequestInputEventHandlerAttributeInjection() {
    // Attribute-injection XSS carries no full tag, only an event handler.
    var result =
        engine.detectMarkupParameter(request(Map.of("name", List.of("\" onerror=alert(1) x=\""))));

    assertTrue(result.isPresent());
    assertEquals("xss_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresBenignHtmlMarkupInRequestParameters() {
    // Legitimate HTML-bearing input (comments, rich text, markup, search terms)
    // must not trip xss_userinput — it is not an XSS execution vector.
    for (String benign :
        List.of(
            "I love <b>bold</b> and <i>italic</i> text",
            "<p>Hello world</p>",
            "<div class=\"card\"><a href=\"/home\">home</a></div>",
            "<html><body><h1>Title</h1></body></html>",
            "online=true&onboarding=1")) {
      var result = engine.detectMarkupParameter(request(Map.of("comment", List.of(benign))));
      assertTrue(
          result.isEmpty() || !"xss_userinput".equals(result.orElseThrow().algorithm()),
          "benign markup should not trip xss_userinput: " + benign);
    }
  }

  @Test
  void detectsJavaBeanClassLoaderPollutionParameter() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
                    List.of("%{c2}i"))));

    assertAlgorithm(result, "request_java_bean_pollution");
  }

  @Test
  void detectsSpringCve202222965TomcatAccessLogValveBindingAndRedactsPayload() {
    String parameter =
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern";
    String payload =
        "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))) { "
            + "java.lang.Runtime.getRuntime().exec(request.getParameter(\"cmd\")); } %{suffix}i";
    String query =
        parameter
            + "=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))"
            + "%7Bjava.lang.Runtime.getRuntime().exec(request.getParameter(%22cmd%22));%7D"
            + "%25%7Bsuffix%7Di"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";
    var parameters = new LinkedHashMap<String, List<String>>();
    parameters.put(parameter, List.of(payload));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix",
        List.of(".jsp"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.directory",
        List.of("webapps/ROOT"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix",
        List.of("tomcatwar"));
    parameters.put(
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat",
        List.of(""));
    var context =
        new RequestContext(
            "GET",
            "/",
            query,
            parameters,
            Map.of("user-agent", "JUnit", "suffix", "%>//", "c1", "Runtime", "c2", "<%"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_java_bean_pollution");
    var detection = result.orElseThrow();
    assertEquals(parameter, detection.details().get("parameter"));
    assertEquals("[redacted]", detection.request().parameters().get(parameter).get(0));
    assertFalse(detection.request().query().contains("getRuntime"));
    assertFalse(detection.request().query().contains("tomcatwar"));
  }

  @Test
  void detectsBracketedJavaBeanClassLoaderPollutionParameter() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "class[module][classLoader][resources][context][parent][pipeline][first][suffix]",
                    List.of(".jsp"))));

    assertAlgorithm(result, "request_java_bean_pollution");
  }

  @Test
  void ignoresOrdinaryClassRequestParameters() {
    var result =
        engine.detectRequest(
            request(
                Map.of(
                    "className", List.of("com.example.Widget"),
                    "module", List.of("catalog"),
                    "classLoaderName", List.of("app"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRawPathTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/geo/../dataease/de2api/datasource/types"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsPathParameterTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/public/..;/admin/"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsShiroCve20201957SemicolonTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/xxx/..;/admin/"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsDotSegmentAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/./admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsShiroCve20103863DotSegmentAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/./admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsDuplicateSlashAuthBypassShape() {
    var result = engine.detectRequest(requestUri("//admin"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void ignoresDotSegmentOnOrdinaryStaticPath() {
    var result = engine.detectRequest(requestUri("/assets/./logo.png"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresCanonicalSensitiveControlPathWithoutConfusion() {
    var result = engine.detectRequest(requestUri("/admin"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsEncodedPathTraversalAuthBypassShape() {
    var result = engine.detectRequest(requestUri("/%2F%2F..%2F..%2Fetc%2Fpasswd"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsNexusCve20244956EncodedSlashPathTraversalShape() {
    var uri =
        "/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsFlinkDoubleEncodedLogPathTraversalShape() {
    var uri =
        "/jobmanager/logs/"
            + "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/jobmanager/logs/../../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsElasticsearchCve20153337PluginPathTraversalShape() {
    var result =
        engine.detectRequest(requestUri("/_plugin/head/../../../../../../../../../etc/passwd"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/_plugin/head/../../../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsElasticsearchCve20155531SnapshotEncodedPathTraversalShape() {
    var uri = "/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd";

    var result = engine.detectRequest(requestUri(uri));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/_snapshot/test/backdata/../../../../../../../etc/passwd",
        result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsEncodedControlCharacterOnSensitivePath() {
    var result = engine.detectRequest(requestUri("/admin/%0atest"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin/\ntest", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsEncodedCarriageReturnOnSensitivePath() {
    var result = engine.detectRequest(requestUri("/admin/%0dtest"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals("/admin/\rtest", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void ignoresEncodedControlCharacterOnOrdinaryPath() {
    var result = engine.detectRequest(requestUri("/assets/%0abanner.png"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsUnicodeGhostBitsPathTraversalShape() {
    var result = engine.detectRequest(requestUri("/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsSpringJettyGhostBitsPathTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri("/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsSpringCve202541242VulhubGhostBitsTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri(
                "/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64"));

    assertAlgorithm(result, "request_path_confusion");
    assertTrue(result.orElseThrow().details().get("decoded").contains("/../"));
  }

  @Test
  void detectsJettyLenientHexPathTraversalShape() {
    var result =
        engine.detectRequest(requestUri("/setup/setup-s/%2>%2>/%2>%2>/user-create.jsp"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsOpenfireUnicodeEscapedSetupTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri("/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp"));

    assertAlgorithm(result, "request_path_confusion");
    assertEquals(
        "/setup/setup-s/../../user-create.jsp", result.orElseThrow().details().get("decoded"));
  }

  @Test
  void detectsDoubleEncodedJettyLenientHexPathTraversalShape() {
    var result = engine.detectRequest(requestUri("/setup/setup-s/%252>%252>/admin.jsp"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsOverlongUtf8PathTraversalShape() {
    var result =
        engine.detectRequest(
            requestUri(
                "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsThreeByteOverlongUtf8PathTraversalShape() {
    var result = engine.detectRequest(requestUri("/theme/%e0%80%ae%e0%80%ae/admin"));

    assertAlgorithm(result, "request_path_confusion");
  }

  @Test
  void detectsJettyConcatDoubleDecodedProtectedResourceQuery() {
    var result = engine.detectRequest(requestTarget("GET", "/static", "/%2557EB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("query", result.orElseThrow().details().get("component"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("double-decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyEncodedDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%2e/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("uri", result.orElseThrow().details().get("component"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyUnicodeDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%u002e/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("unicode-decoded", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyNulDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/.%00/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("nul-segment", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsJettyNulDotDotProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/a/b/..%00/WEB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("nul-segment", result.orElseThrow().details().get("variant"));
  }

  @Test
  void detectsEncodedProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/%57EB-INF/web.xml"));

    assertAlgorithm(result, "request_internal_resource");
  }

  @Test
  void ignoresDirectProtectedResourcePath() {
    var result = engine.detectRequest(requestUri("/WEB-INF/web.xml"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignDoubleEncodedQueryResource() {
    var result = engine.detectRequest(requestTarget("GET", "/static", "/css/%2562ase.css"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresEncodedProtectedResourceInsideOrdinaryQueryParameter() {
    var result = engine.detectRequest(requestTarget("GET", "/search", "uri=%2fMETA-INF%2fMANIFEST.MF"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignEncodedRequestPath() {
    var result = engine.detectRequest(requestUri("/files/report%202026.txt"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignJettyLenientHexPath() {
    var result = engine.detectRequest(requestUri("/files/%2>report.txt"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignOverlongUtf8PathSeparator() {
    var result = engine.detectRequest(requestUri("/assets%c0%afimages/logo.png"));

    assertTrue(result.isEmpty());
  }

  private static RequestContext requestTarget(String method, String uri, String query) {
    return new RequestContext(method, uri, query, Map.of(), Map.of("user-agent", "JUnit"));
  }

  private static String basic(String username, String password) {
    return "Basic "
        + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
  }
}
