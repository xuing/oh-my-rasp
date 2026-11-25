package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** FileAccessDetector: File reads, directory listings, @file argument expansion, includes and forged include attributes. */
final class FileAccessDetectorTest {
  @ParameterizedTest
  @ValueSource(strings = {"../reports/private.txt", "../../backup/users.zip"})
  void recognizesTraversalToOrdinaryFileTypes(String relative) {
    assertAlgorithm(FileAccessDetector.detectFileRead("/srv/public/" + relative,
        request(Map.of("path", List.of(relative))), false), "readFile_userinput");
  }

  @Test
  void recognizesRequestRelativeToProtectedWebappDirectory() {
    var ctx = request(Map.of("file", List.of("WEB-INF/web.xml")));
    assertAlgorithm(FileAccessDetector.detectFileRead("/app/WEB-INF/web.xml", ctx, false), "readFile_userinput");
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsMasterKey() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("help", "@/var/jenkins_home/secrets/master.key"),
            request());

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("args4j", result.orElseThrow().details().get("parser"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForProcEnviron() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("@/proc/self/environ"),
            request(Map.of("arg", List.of("@/proc/self/environ"))));

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("/proc/self/environ", result.orElseThrow().details().get("path"));
  }

  @Test
  void detectsArgs4jArgumentFileExpansionForJenkinsConnectNodePasswd() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("connect-node", "@/etc/passwd"),
            request(Map.of("arg", List.of("connect-node", "@/etc/passwd"))));

    assertAlgorithm(result, "readFile_argument_expansion");
    assertEquals("@/etc/passwd", result.orElseThrow().details().get("argument"));
    assertEquals("/etc/passwd", result.orElseThrow().details().get("path"));
  }

  @Test
  void ignoresRelativeArgs4jArgumentFileExpansion() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j", List.of("@relative/options.txt"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresUnknownArgumentFileExpansionParser() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "picocli", List.of("@/var/jenkins_home/secrets/master.key"), request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBackgroundArgumentFileExpansion() {
    var result =
        FileAccessDetector.detectArgumentFileExpansion(
            "args4j",
            List.of("@/var/jenkins_home/secrets/master.key"),
            RequestContext.empty());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsSensitiveFileRead() {
    var result = FileAccessDetector.detectFileRead("/etc/passwd", request(), false);

    assertTrue(result.isPresent());
    assertEquals("readFile_unwanted", result.orElseThrow().algorithm());
  }

  @Test
  void detectsHttpFileReadFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "http://127.0.0.1/internal",
            request(Map.of("file", List.of("http://127.0.0.1/internal"))),
            false);

    assertAlgorithm(result, "readFile_userinput_http");
  }

  @Test
  void detectsUnwantedFileReadProtocolFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "file:///etc/passwd", request(Map.of("file", List.of("file:///etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsMetabaseGeojsonFileReadProtocolFromUserInput() {
    var result =
        FileAccessDetector.detectFileRead(
            "file:////etc/passwd", request(Map.of("url", List.of("file:////etc/passwd"))), false);

    assertAlgorithm(result, "readFile_userinput_unwanted");
  }

  @Test
  void detectsFileReadOutsideWebroot() {
    assertTrue(FileAccessDetector.detectFileRead("/etc/hosts", request(), false).isEmpty());
    var result = FileAccessDetector.detectFileRead("/etc/hosts", request(), false, true);

    assertAlgorithm(result, "readFile_outsideWebroot");
  }

  @Test
  void detectsXxeFileReadFromParserStackHint() {
    var result = FileAccessDetector.detectFileRead("/etc/passwd", request(), true);

    assertTrue(result.isPresent());
    assertEquals("xxe_file", result.orElseThrow().algorithm());
  }

  @Test
  void ignoresSimpleParameterNameSubstringInLibraryFileRead() {
    var result =
        FileAccessDetector.detectFileRead(
            "/usr/local/tomcat/webapps/ROOT/WEB-INF/lib/spring-expression-7.0.7.jar",
            request(Map.of("expr", List.of("T(java.lang.Runtime).getRuntime().exec('id')"))),
            false);

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsDirectoryUserInput() {
    var result = FileAccessDetector.detectDirectoryList("/etc", request(Map.of("path", List.of("/etc"))));

    assertTrue(result.isPresent());
    assertEquals("directory_userinput", result.orElseThrow().algorithm());
  }

  @Test
  void separatesTomcatDeploymentScanFromApplicationDirectoryListing() {
    var scan = List.of("java.io.File", "org.apache.catalina.webresources.DirResourceSet",
        "org.apache.catalina.startup.ContextConfig", "java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/app/WEB-INF/classes", RequestContext.empty(), scan).isEmpty());
    assertTrue(FileAccessDetector.detectDirectoryList("/root", RequestContext.empty(), scan).isEmpty());
    var app = List.of("java.io.File", "example.Initializer",
        "org.apache.catalina.startup.ContextConfig", "java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/data", RequestContext.empty(), app).isEmpty());
    var reflective = List.of("java.io.File", "java.lang.reflect.Method", "example.Initializer");
    assertTrue(FileAccessDetector.detectDirectoryList("/data", RequestContext.empty(), reflective).isEmpty());
  }

  @Test
  void fixedDirectoryLocationAndReflectionRequireExplicitRules() {
    var stack = List.of("java.lang.reflect.Method");
    assertTrue(FileAccessDetector.detectDirectoryList("/root", request(), stack).isEmpty());
    var candidates = FileAccessDetector.directoryListings("/root", request(), null, false, false, false,
        algorithm -> true, () -> stack);
    assertEquals(List.of("directory_unwanted", "directory_reflect"), candidates.stream().map(Detection::algorithm).toList());
    assertTrue(candidates.stream().allMatch(Detection::requiresExplicitRule));
  }

  @Test
  void detectsIncludeUserInput() {
    var result =
        FileAccessDetector.detectInclude(
            "/etc/passwd", "/etc/passwd", "include", request(Map.of("file", List.of("/etc/passwd"))));

    assertAlgorithm(result, "include_userinput");
  }

  @Test
  void detectsIncludeProtocol() {
    var result = FileAccessDetector.detectInclude("jar://file:/tmp/a.jar!/x", "", "include", request());

    assertAlgorithm(result, "include_protocol");
  }

  @Test
  void detectsForgedServletIncludeAttributeForProtectedResource() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/WEB-INF/web.xml"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("protected-resource", result.orElseThrow().details().get("targetType"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals(
        "servlet-include-attribute", result.orElseThrow().details().get("source"));
  }

  @Test
  void detectsTomcatGhostcatAjpIncludeAttributes() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of(
                "javax.servlet.include.request_uri",
                "/",
                "javax.servlet.include.path_info",
                "WEB-INF/web.xml",
                "javax.servlet.include.servlet_path",
                "/"),
            requestUri("/asdf"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("protected-resource", result.orElseThrow().details().get("targetType"));
    assertEquals("WEB-INF", result.orElseThrow().details().get("resource"));
    assertEquals("/asdf", result.orElseThrow().details().get("uri"));
  }

  @Test
  void detectsForgedServletIncludeAttributeForServerSideScript() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("jakarta.servlet.include.path_info", "/uploads/shell.jsp"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertAlgorithm(result, "request_forged_include_attribute");
    assertEquals("server-side-script", result.orElseThrow().details().get("targetType"));
  }

  @Test
  void ignoresLegitimateRequestDispatcherIncludeStack() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/WEB-INF/jsp/view.jsp"),
            requestUri("/page"),
            List.of("org.apache.catalina.core.ApplicationDispatcher", "com.example.View"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresSafeServletIncludeAttributeTarget() {
    var result =
        FileAccessDetector.detectServletIncludeAttributes(
            Map.of("javax.servlet.include.servlet_path", "/assets/logo.png"),
            requestUri("/"),
            List.of("org.apache.coyote.ajp.AjpProcessor"));

    assertTrue(result.isEmpty());
  }
}
