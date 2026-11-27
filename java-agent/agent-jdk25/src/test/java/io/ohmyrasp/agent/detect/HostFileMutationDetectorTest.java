package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorTestSupport.assertAlgorithm;
import static io.ohmyrasp.agent.detect.DetectorTestSupport.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.ohmyrasp.agent.model.RequestContext;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** HostFileMutationDetector: Host file writes, deletes, archive extraction, renames, links and generated scripts. */
final class HostFileMutationDetectorTest {
  @Test
  void correlatesManagedArgumentsWithAnObservedWrite() {
    String selected = "/reports/weekly.jsp";
    for (String argument : List.of(selected, "<report destination=\"" + selected + "\"/>")) {
      Object opened = io.ohmyrasp.agent.jmx.JmxWriteScope.enter();
      try {
        var values = List.of(argument);
        io.ohmyrasp.agent.jmx.JmxWriteScope.select("reports:type=Writer", "publish", values);
        assertTrue(RemoteResourceDetector.detectJmxMBeanInvoke("reports:type=Writer", "publish", values, request()).isEmpty());
        var scope = io.ohmyrasp.agent.jmx.JmxWriteScope.current();
        assertTrue(HostFileMutationDetector.detectJmxFileWrite("/reports/other.jsp", scope, "channel_open", request()).isEmpty());
        var detection = HostFileMutationDetector.detectJmxFileWrite(selected, scope, "channel_open", request());
        assertAlgorithm(detection, "jmx_file_write");
        assertEquals("selected_write_open", detection.get().details().get("decision_basis"));
      } finally {
        io.ohmyrasp.agent.jmx.JmxWriteScope.exit(opened);
      }
    }
  }

  @Test
  void detectsScriptFileWrite() {
    var result = HostFileMutationDetector.detectFileWrite("/usr/local/tomcat/webapps/ROOT/shell.jsp", request());

    assertTrue(result.isPresent());
    assertEquals("writeFile_script", result.orElseThrow().algorithm());
  }

  /** Outside a request the script-write rule of the backports decides, on every line. */
  @Test
  void decidesScriptWritesOutsideARequestWithTheBackportRule() {
    assertAlgorithm(HostFileMutationDetector.detectFileWrite("/usr/local/tomcat/webapps/ROOT/shell.jsp",
        RequestContext.empty()), "writeFile_script");
    assertAlgorithm(HostFileMutationDetector.detectFileWrite("/srv/upload/../webapps/ROOT/x.war",
        RequestContext.empty()), "writeFile_script");
    for (String benign : List.of("/tmp/report.jsp", "/srv/app/webapps/ROOT/WEB-INF/lib/app.jar",
        "/home/build/.m2/repository/org/example/lib/1.0/lib-1.0.jar", "/usr/local/tomcat/webapps/ROOT/index.html")) {
      assertTrue(HostFileMutationDetector.detectFileWrite(benign, RequestContext.empty()).isEmpty(), benign);
    }
  }

  @Test
  void distinguishesDirectReflectiveWriteFromOrdinaryBackgroundWrite() {
    String path = "/srv/app/views/order.jsp";
    var ordinary = List.of("java.io.FileOutputStream", "app.Renderer", "java.lang.reflect.Method");
    assertTrue(HostFileMutationDetector.detectFileWrite(path, RequestContext.empty(), ordinary).isEmpty());
    var direct = List.of("java.io.FileOutputStream", "java.io.FileOutputStream", "java.lang.reflect.Constructor");
    assertAlgorithm(HostFileMutationDetector.detectFileWrite(path, RequestContext.empty(), direct), "writeFile_reflect");
  }

  @Test
  void appliesFilePolicyToTheDefaultWindowsStreamAndRequiresASelectorForNamedStreams() {
    var ordinary = new io.ohmyrasp.agent.file.WindowsDataStream("weekly.csv", "");
    var script = new io.ohmyrasp.agent.file.WindowsDataStream("report.jsp", "");
    var metadata = new io.ohmyrasp.agent.file.WindowsDataStream("weekly.csv", "author");
    assertTrue(HostFileMutationDetector.detectWindowsStreamWrite(ordinary, request(), List.of(), true).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectWindowsStreamWrite(script, request(), List.of(), false), "writeFile_script");
    assertTrue(HostFileMutationDetector.detectWindowsStreamWrite(metadata, request(), List.of(), false).isEmpty());
    var selected = HostFileMutationDetector.detectWindowsStreamWrite(metadata, request(), List.of(), true).orElseThrow();
    assertEquals("writeFile_NTFS", selected.algorithm());
    assertEquals("author", selected.details().get("stream"));
    assertTrue(selected.requiresExplicitRule());
    assertTrue(FileUploadDetector.detectFileUpload("weekly.csv::$DATA", request()).isEmpty());
  }

  @Test
  void detectsReflectiveJspFileWrite() {
    var result =
        HostFileMutationDetector.detectFileWrite(
            "/usr/local/tomcat/webapps/ROOT/shell.jsp",
            request(),
            List.of("java.lang.reflect.Method", "shell.Backdoor"));

    assertAlgorithm(result, "writeFile_reflect");
  }

  @Test
  void detectsOpenTsdbCve202035476GeneratedGnuplotYrangeScriptWrite() {
    String payload = "[0:system('touch /tmp/success')]";
    String content = "set yrange " + payload + "\nplot '-' using 1:2";

    var result =
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
            "/tmp/opentsdb-plot.gnuplot",
            content,
            request(Map.of("yrange", List.of(payload))));

    assertAlgorithm(result, "writeFile_generated_script");
  }

  @Test
  void detectsOpenTsdbCve202325826GeneratedGnuplotKeyScriptWrite() {
    String payload = ";system \"touch /tmp/poc\" \"";
    String content = "set key " + payload + "\nplot '-' using 1:2";

    var result =
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
            "/tmp/tsd-graph.gp",
            content,
            request(Map.of("key", List.of(payload))));

    assertAlgorithm(result, "writeFile_generated_script");
  }

  @Test
  void distinguishesProgramOperationsFromTemporaryReportData() {
    String op = "system(\"printf weekly\")";
    var ctx = request(Map.of("label", List.of(op)));
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "# " + op, ctx).isEmpty());
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "title = '" + op + "'", ctx).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "value = " + op, ctx), "writeFile_generated_script");
    assertTrue(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "label = 'North'\nvalue = " + op,
        request(Map.of("label", List.of("North")))).isEmpty());
    assertAlgorithm(HostFileMutationDetector.detectGeneratedScriptFileWrite("/tmp/report", "value = " + op,
        request(Map.of("value", List.of("printf weekly")))), "writeFile_generated_script");
  }

  @Test
  void ignoresBenignGeneratedGnuplotScriptWrite() {
    var result =
        HostFileMutationDetector.detectGeneratedScriptFileWrite(
            "/tmp/opentsdb-plot.gnuplot",
            "set yrange [0:42]\nplot '-' using 1:2",
            request(Map.of("yrange", List.of("[0:42]"))));

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRocketMqCve202337582UnsafeConfigPersistenceFileWrite() {
    var result =
        HostFileMutationDetector.detectFileWrite(
            "/tmp/success",
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.remoting.Configuration",
                "org.apache.rocketmq.common.MixAll"));

    assertAlgorithm(result, "writeFile_config_path");
    assertEquals(
        "org.apache.rocketmq.remoting.Configuration",
        result.orElseThrow().details().get("persistence"));
  }

  @Test
  void ignoresNormalConfigPersistenceFileWrite() {
    var result =
        HostFileMutationDetector.detectFileWrite(
            "/root/namesrv/namesrv.properties",
            RequestContext.empty(),
            List.of(
                "org.apache.rocketmq.remoting.Configuration",
                "org.apache.rocketmq.common.MixAll"));

    assertTrue(result.isEmpty());
  }

  @Test
  void distinguishesDeletePathControlFromAReportIdentifier() {
    String absolute = "/srv/docs/report-10.txt";
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("week", List.of("10")))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("file", List.of("report-10.txt")))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete(absolute, request(Map.of("file", List.of(absolute)))).isEmpty());
    String protectedEntry = "/srv/docs/WEB-INF/report.xml";
    assertTrue(HostFileMutationDetector.detectFileDelete(protectedEntry, request(Map.of("file", List.of(protectedEntry)))).isEmpty());
    assertTrue(HostFileMutationDetector.detectFileDelete("/srv/docs/../note.txt",
        request(Map.of("file", List.of("../note.txt")))).isEmpty());
  }

  @Test
  void detectsArchiveTraversalExtraction() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/../escaped/archive.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void detectsAbsoluteArchiveEntryExtraction() {
    var result = HostFileMutationDetector.detectArchiveExtraction("/tmp/evil.txt", "/tmp/evil.txt", request());

    assertAlgorithm(result, "archive_traversal");
  }

  @Test
  void ignoresNormalArchiveEntryExtraction() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "docs/readme.txt", "/tmp/ohmyrasp/root/docs/readme.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void requiresAnEscapingMemberAndCorrespondingWritePath() {
    for (String[] paths : new String[][] {
        {"drafts/../report.txt", "/out/drafts/../report.txt"},
        {"../out/report.txt", "/tmp/out/../out/report.txt"},
        {"../report.txt", "/out/drafts/../report.txt.bak"},
        {"../notes/report.txt", "/out/drafts/../report.txt"},
        {"/notes/report.txt", "/out/notes/report.txt"},
        {" ../report.txt", "/out/ ../report.txt"}
    }) {
      assertTrue(HostFileMutationDetector.detectArchiveExtraction(paths[0], paths[1], request()).isEmpty());
    }
    assertAlgorithm(HostFileMutationDetector.detectArchiveExtraction("..\\report.txt",
        "/out/../report.txt", request()), "archive_traversal");
    assertAlgorithm(HostFileMutationDetector.detectArchiveExtraction("drafts/../../report.txt",
        "/out/drafts/../../report.txt", request()), "archive_traversal");
  }

  @Test
  void ignoresSanitizedArchiveTraversalEntry() {
    var result =
        HostFileMutationDetector.detectArchiveExtraction(
            "../escaped/archive.txt", "/tmp/ohmyrasp/root/safe/archive.txt", request());

    assertTrue(result.isEmpty());
  }

  @Test
  void detectsRenameWebshell() {
    var result = HostFileMutationDetector.detectRename("avatar.jpg", "shell.jsp", request());

    assertAlgorithm(result, "rename_webshell");
  }

  @Test
  void detectsLinkWebshell() {
    var result = HostFileMutationDetector.detectLink("avatar.jpg", "shell.jsp", "hard", request());

    assertAlgorithm(result, "link_webshell");
  }

  @Test
  void detectsWebshellFilePutContents() {
    var result =
        HostFileMutationDetector.detectWebshellFileWrite(
            "shell.jsp", "<% out.println(1); %>", request(Map.of("file", List.of("shell.jsp"))));

    assertAlgorithm(result, "webshell_file_put_contents");
  }
}
