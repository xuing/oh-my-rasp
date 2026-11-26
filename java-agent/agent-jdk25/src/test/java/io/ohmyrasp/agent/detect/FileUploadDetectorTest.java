package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.requestUri;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.http.ArchiveUploadPolicy;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** FileUploadDetector: Upload file names and WebDAV move or copy destinations. */
final class FileUploadDetectorTest {
  @Test
  void detectsMultipartScriptUpload() {
    var result = FileUploadDetector.detectFileUpload("shell.jsp", request());

    assertAlgorithm(result, "fileUpload_multipart_script");
  }

  @Test
  void detectsWebLogicWsUtcJspUpload() {
    RequestContext request =
        new RequestContext(
            "POST",
            "/ws_utc/resources/setting/keystore",
            "",
            Map.of(),
            Map.of("content-type", "multipart/form-data; boundary=ohmyrasp"));

    var result = FileUploadDetector.detectFileUpload("shell.jsp", request);

    assertAlgorithm(result, "fileUpload_multipart_script");
    assertEquals("/ws_utc/resources/setting/keystore", result.orElseThrow().request().uri());
    assertEquals("shell.jsp", result.orElseThrow().details().get("filename"));
  }

  @Test
  void detectsMultipartUploadPathTraversal() {
    var result = FileUploadDetector.detectFileUpload("../../../../../../tmp/success", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void detectsMultipartOgnlFilenameExpression() {
    var filename =
        "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
            + ".addHeader('X-Test',233*233)}\u0000b";

    var result = FileUploadDetector.detectFileUpload(filename, request());

    assertAlgorithm(result, "fileUpload_multipart_expression");
    assertEquals("ognl", result.orElseThrow().details().get("engine"));
    assertEquals(String.valueOf(filename.length()), result.orElseThrow().details().get("filenameLength"));
    assertFalse(result.orElseThrow().details().containsKey("filename"));
  }

  @Test
  void detectsEncodedMultipartUploadPathTraversal() {
    var result = FileUploadDetector.detectFileUpload("..%2f..%2f..%2fvar%2flog%2fapp.txt", request());

    assertAlgorithm(result, "fileUpload_path_traversal");
  }

  @Test
  void ignoresMultipartUploadSubdirectoryFilename() {
    var result = FileUploadDetector.detectFileUpload("reports/summary.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresBenignExpressionLikeMultipartFilename() {
    var result = FileUploadDetector.detectFileUpload("report-%{yyyy}.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsMultipartHtmlUpload() {
    var result = FileUploadDetector.detectFileUpload("phish.html", request());

    assertAlgorithm(result, "fileUpload_multipart_html");
  }

  @Test
  void detectsMultipartExecutableUpload() {
    var result = FileUploadDetector.detectFileUpload("dropper.exe", request());

    assertAlgorithm(result, "fileUpload_multipart_exe");
  }

  @Test
  void collectsPluginUploadCandidateForManagedPolicy() {
    var result = FileUploadDetector.detectFileUpload("Evil.jar", requestUri("/plugin/add"),
            ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void collectsJarUploadCandidateForManagedPolicy() {
    var result = FileUploadDetector.detectFileUpload("Exploit.jar", requestUri("/jars/upload"),
            ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void collectsJarParameterCandidateForManagedPolicy() {
    var request =
        new RequestContext(
            "POST", "/upload", "", Map.of("jarfile", List.of("selected")), Map.of());
    var result = FileUploadDetector.detectFileUpload("Exploit.jar", request, ArchiveUploadPolicy.Decision.UNSPECIFIED, true);

    assertAlgorithm(result, "fileUpload_java_archive");
  }

  @Test
  void archiveFilenameAloneDoesNotEstablishAuthorization() {
    var request = requestUri("/plugin/add");
    assertTrue(FileUploadDetector.detectFileUpload("release.jar", request).isEmpty());
    assertTrue(FileUploadDetector.detectFileUpload("release.jar", request, ArchiveUploadPolicy.Decision.ALLOWED, false).isEmpty());
    var denied = FileUploadDetector.detectFileUpload("release.jar", request, ArchiveUploadPolicy.Decision.ROLE_DENIED, false);
    assertAlgorithm(denied, "fileUpload_java_archive");
    assertEquals("required_role_denied", denied.orElseThrow().details().get("decision_basis"));
  }

  @Test
  void ignoresJavaArchiveRepositoryUpload() {
    var result = FileUploadDetector.detectFileUpload("library.jar", requestUri("/service/rest/v1/components"));

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresJavaArchiveUploadOnUnrelatedForm() {
    var result = FileUploadDetector.detectFileUpload("library.jar", requestUri("/profile/avatar"));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsWebdavUpload() {
    var result = FileUploadDetector.detectWebdavUpload("avatar.jpg", "shell.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
  }

  @Test
  void detectsWebdavUploadToUnsafeFilesystemDestination() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("unsafe-filesystem-path", result.orElseThrow().details().get("destinationType"));
    assertEquals("/etc/cron.d/root", result.orElseThrow().details().get("destinationPath"));
  }

  @Test
  void detectsActiveMqFileserverMoveToWebshell() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/2.txt", "file:///opt/activemq/webapps/api/s.jsp", "MOVE", request());

    assertAlgorithm(result, "fileUpload_webdav");
    assertEquals("server-side-script", result.orElseThrow().details().get("destinationType"));
    assertEquals("/fileserver/2.txt", result.orElseThrow().details().get("source"));
  }

  @Test
  void ignoresBenignWebdavUploadMove() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/avatar.jpg", "/fileserver/avatar-renamed.jpg", "MOVE", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void ignoresWebdavUploadDestinationForReadOnlyMethod() {
    var result =
        FileUploadDetector.detectWebdavUpload(
            "/fileserver/1.txt", "file:///etc/cron.d/root", "GET", request());

    assertTrue(result.isEmpty());
  }
}
