import io.ohmyrasp.agent.detect.DetectorEngine;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * False-positive measurement harness.
 *
 * <p>Runs a curated corpus of <em>benign but plausible</em> inputs through the
 * real {@link DetectorEngine} and counts how many produce a detection. Each
 * input is presented with a realistic request context: where a value would
 * normally be user-supplied, it is placed in a request parameter so taint-aware
 * detectors see it exactly as they would in production.
 *
 * <p>A "false positive" here is any detector returning a {@link Detection} for
 * an input drawn from legitimate application behavior. This measures detector
 * precision on benign-but-suspicious-looking traffic; it is a detector-level
 * probe, not a production-traffic FP rate. The corpus and every false positive
 * are printed so the number is fully auditable. Emits Markdown to stdout.
 */
public final class FpReport {
  private static final DetectorEngine ENGINE = new DetectorEngine();

  /** A benign case: a payload and, when applicable, the user-supplied token embedded in it. */
  record Case(String payload, String userParam) {
    static Case of(String payload) {
      return new Case(payload, null);
    }
    static Case tainted(String payload, String userParam) {
      return new Case(payload, userParam);
    }
  }

  record Category(String name, List<Case> cases, java.util.function.BiFunction<Case, RequestContext, Optional<Detection>> run) {}

  public static void main(String[] args) {
    List<Category> categories = List.of(
        new Category("Internationalized report routes", List.of(
            Case.of("/admin/reports/資料"),
            Case.of("/admin/reports/%E6%9D%B1%E4%BA%AC"),
            Case.of("/admin/reports/%C5%81%C3%B3d%C5%BA"),
            Case.of("/admin/reports/%F0%9F%93%8A"),
            Case.of("/admin/reports/%25E6%259D%25B1"),
            Case.of("/admin/reports/%31%32-%F0%9F%93%8A.csv")),
            (c, r) -> ENGINE.detectRequest(new RequestContext("GET", c.payload(), "", Map.of(), Map.of()))),
        new Category("Report field metadata", List.of(
            Case.of("{\"orders\":[{\"type\":\"# report heading\"}]}"),
            Case.of("{\"table\":\"reports\",\"column\":\"Select title\"}")),
            (c, r) -> ENGINE.detectRequest(new RequestContext("POST", "/reports/query", "",
                Map.of(), Map.of("content-type", "application/json"), c.payload()))),
        new Category("SQL queries", sqlCorpus(), (c, r) -> ENGINE.detectSql(c.payload(), r)),
        new Category("OS commands", commandCorpus(), (c, r) -> ENGINE.detectCommand(splitCommand(c.payload()), r)),
        new Category("Inline shell reports", List.of(
            Case.of("printf '%s' 'example: cat /etc/passwd'"),
            Case.of("printf '%s' weekly # example: cat /etc/passwd"),
            Case.of("cat /etc/passwd.example")),
            (c, r) -> ENGINE.detectCommand(List.of("/bin/sh", "-c", c.payload()), r)),
        new Category("Process dispatch", List.of(
            Case.of("java.lang.reflect.Method"),
            Case.of("example.spelling.MonthlyReport"),
            Case.of("example.javascriptnotes.Catalog"),
            Case.of("example.velocitymetrics.Recorder")),
            (c, r) -> ENGINE.detectCommand(List.of("printf", "%s", "weekly"), r,
                List.of("java.lang.ProcessImpl", "java.lang.ProcessBuilder", c.payload()))),
        new Category("Spark job descriptors", List.of(
            Case.of("{\"action\":\"CreateSubmissionRequest\",\"appResource\":\"https://artifacts.example.test/reports.jar\",\"mainClass\":\"reports.Weekly\"}")),
            (c, r) -> ENGINE.detectRemoteJobSubmission("Spark REST", c.payload(),
                new RequestContext("POST", "/v1/submissions/create", "", Map.of(), Map.of()))),
        new Category("YARN job descriptors", List.of(
            Case.of("{\"am-container-spec\":{\"commands\":{\"command\":\"java reports.Weekly\"}}}"),
            Case.of("{\"am-container-spec\":{\"commands\":{\"command\":\"echo cat /etc/passwd\"}}}")),
            (c, r) -> ENGINE.detectRemoteJobSubmission("YARN", c.payload(),
                new RequestContext("POST", "/ws/v1/cluster/apps", "", Map.of(), Map.of()))),
        new Category("Outbound URLs", urlCorpus(), (c, r) -> ENGINE.detectUrl(c.payload(), r)),
        new Category("File reads", fileReadCorpus(), (c, r) -> ENGINE.detectFileRead(c.payload(), r, false)),
        new Category("Directory listings", List.of(
            Case.tainted("/srv/orders/exports", "orders"),
            Case.tainted("/srv/reports/catalog", "/srv/reports/catalog"),
            Case.of("/etc"),
            Case.of("/proc")),
            (c, r) -> ENGINE.detectDirectoryList(c.payload(), r)),
        new Category("Temporary report output", List.of(
            Case.tainted("{\"api\":\"Runtime.exec(String)\",\"report\":\"weekly\"}", "weekly"),
            Case.tainted("{\"label\":\"Runtime.exec(String)\"}", "Runtime.exec(String)"),
            Case.tainted("# reference: system(\"printf weekly\")", "system(\"printf weekly\")")),
            (c, r) -> ENGINE.detectGeneratedScriptFileWrite("/tmp/reports/document.tmp", c.payload(), r)),
        new Category("File writes", fileWriteCorpus(), (c, r) -> ENGINE.detectFileWrite(c.payload(), r)),
        new Category("File deletes", List.of(
            Case.tainted("/srv/reports/report-10.txt", "10"),
            Case.tainted("/srv/reports/invoice.csv", "invoice.csv"),
            Case.tainted("/srv/reports/invoice.csv", "/srv/reports/invoice.csv"),
            Case.tainted("/srv/app/WEB-INF/work.csv", "/srv/app/WEB-INF/work.csv")),
            (c, r) -> ENGINE.detectFileDelete(c.payload(), r)),
        new Category("Archive writes", List.of(
            Case.tainted("/srv/orders/drafts/../report.csv", "drafts/../report.csv"),
            Case.tainted("/srv/orders/report.csv", "../report.csv"),
            Case.tainted("/srv/orders/../orders/report.csv", "../orders/report.csv"),
            Case.tainted("/srv/orders/notes/report.csv", "/notes/report.csv"),
            Case.tainted("/srv/orders/drafts/../report.csv.bak", "../report.csv")),
            (c, r) -> ENGINE.detectArchiveExtraction(c.userParam(), c.payload(), r)),
        new Category("Deserialization classes", deserializationCorpus(), (c, r) -> ENGINE.detectDeserialization(c.payload(), r)),
        new Category("Expressions", expressionCorpus(), (c, r) -> ENGINE.detectExpression("spel", c.payload(), r)),
        new Category("OGNL expressions", ognlCorpus(), (c, r) -> ENGINE.detectOgnl(c.payload(), r)),
        new Category("JNDI names", jndiCorpus(), (c, r) -> ENGINE.detectJndi(c.payload(), r)),
        new Category("DNS lookups", dnsCorpus(), (c, r) -> ENGINE.detectDns(c.payload(), r)),
        new Category("Ordinary deployment uploads", List.of(
            Case.of("weekly.jar"), Case.of("component.war"), Case.of("connector.ear")),
            (c, r) -> ENGINE.detectFileUpload(c.payload(),
                new RequestContext("POST", "/plugin/add", "", Map.of(), Map.of()))),
        new Category("Upload filenames", uploadCorpus(), (c, r) -> ENGINE.detectFileUpload(c.payload(), r)),
        new Category("JDBC URLs", jdbcCorpus(), (c, r) -> ENGINE.detectJdbcUrl(c.payload(), r)),
        new Category("Application response markup", List.of(
            Case.tainted("<script src='/assets/report.js'></script>", "weekly"),
            Case.tainted("<p>&lt;script&gt;</p>", "<script>")),
            (c, r) -> ENGINE.detectXssEcho(c.payload(), r)),
        new Category("Request parameters", requestParamCorpus(), (c, r) -> ENGINE.detectRequest(r)),
        new Category(
            "Base64 decoding",
            base64Corpus(),
            (c, r) ->
                ENGINE.detectBase64Decode(
                    c.payload().getBytes(StandardCharsets.ISO_8859_1),
                    0,
                    c.payload().length(),
                    "urlsafe".equals(c.userParam()),
                    "mime".equals(c.userParam()),
                    r)));

    int totalCases = 0;
    int totalFp = 0;
    StringBuilder detail = new StringBuilder();
    List<String[]> summaryRows = new ArrayList<>();

    for (Category category : categories) {
      int fp = 0;
      List<String> fpDetails = new ArrayList<>();
      for (Case benign : category.cases()) {
        RequestContext request = request(benign.userParam());
        Optional<Detection> detection = category.run().apply(benign, request);
        if (detection.isPresent()) {
          fp++;
          Detection d = detection.get();
          fpDetails.add("`" + d.algorithm() + "` ⇐ `" + abbreviate(benign.payload()) + "`");
        }
      }
      totalCases += category.cases().size();
      totalFp += fp;
      double rate = category.cases().isEmpty() ? 0 : (100.0 * fp / category.cases().size());
      summaryRows.add(new String[] {
          category.name(),
          String.valueOf(category.cases().size()),
          String.valueOf(fp),
          String.format("%.1f%%", rate)
      });
      if (!fpDetails.isEmpty()) {
        detail.append("\n### ").append(category.name()).append(" false positives\n\n");
        for (String line : fpDetails) {
          detail.append("- ").append(line).append('\n');
        }
      }
    }

    double overall = totalCases == 0 ? 0 : (100.0 * totalFp / totalCases);

    StringBuilder out = new StringBuilder();
    out.append("# OhMyRASP False-Positive Report\n\n");
    out.append("> **Generated** by `scripts/fp-harness/FpReport.java` against the real `DetectorEngine`.\n");
    out.append("> Re-run via `scripts/run-fp-report.sh` after changing detectors.\n\n");
    out.append("## Method\n\n");
    out.append("A curated corpus of **").append(totalCases).append("** benign-but-plausible inputs across **")
        .append(categories.size()).append("** detector categories is run through the engine. Each input is ")
        .append("presented with a realistic request context; where a value would be user-supplied it is placed ")
        .append("in a request parameter so taint-aware detectors evaluate it as in production. A *false positive* ")
        .append("is any detector returning a detection for legitimate input. This is a detector-precision probe on ")
        .append("benign traffic, **not** a production-traffic false-positive rate.\n\n");
    out.append("## Result\n\n");
    out.append("| Category | Benign inputs | False positives | FP rate |\n");
    out.append("|----------|--------------:|----------------:|--------:|\n");
    for (String[] row : summaryRows) {
      out.append("| ").append(row[0]).append(" | ").append(row[1]).append(" | ")
          .append(row[2]).append(" | ").append(row[3]).append(" |\n");
    }
    out.append("| **Overall** | **").append(totalCases).append("** | **").append(totalFp)
        .append("** | **").append(String.format("%.1f%%", overall)).append("** |\n");
    if (detail.length() > 0) {
      out.append("\n## False positives observed\n").append(detail);
      out.append("\n> Each line above is a legitimate input that tripped a detector. These are the ")
          .append("precision edges to tune (taint scope, allowlist, confidence thresholds).\n");
    } else {
      out.append("\nNo false positives observed across the corpus.\n");
    }
    out.append("\n## Corpus\n\n<details><summary>All benign inputs tested</summary>\n\n");
    for (Category category : categories) {
      out.append("**").append(category.name()).append("**\n\n");
      for (Case benign : category.cases()) {
        out.append("- `").append(abbreviate(benign.payload())).append('`');
        if (benign.userParam() != null) {
          out.append(" (user input: `").append(benign.userParam()).append("`)");
        }
        out.append('\n');
      }
      out.append('\n');
    }
    out.append("</details>\n");

    System.out.print(out);
    if (List.of(args).contains("--check") && totalFp != 0) {
      throw new AssertionError(totalFp + " benign inputs triggered detections:" + detail);
    }
  }

  private static RequestContext request(String userParam) {
    Map<String, List<String>> parameters =
        userParam == null ? Map.of() : Map.of("input", List.of(userParam));
    return new RequestContext("GET", "/app/action", "", parameters, Map.of("user-agent", "Mozilla/5.0"));
  }

  private static List<String> splitCommand(String joined) {
    return List.of(joined.split(" "));
  }

  private static List<Case> sqlCorpus() {
    return List.of(
        Case.tainted("select * from notes where title = 'union select'", "union select"),
        Case.tainted("select * from notes where label = 'build--release'", "build--release"),
        Case.of("insert into audit(message) values ('user''s sleep(5) example')"),
        Case.tainted("/* mapped query */ select id from orders where id = 42", "42"),
        Case.of("select 'SQLJ.INSTALL_JAR( documentation' as excerpt"),
        Case.of("/* CREATE ALIAS using ProcessBuilder is documented separately */ select 7"),
        Case.of("select 'RUNSCRIPT FROM https://docs.invalid/manual' as excerpt"),
        Case.tainted("select 'catalog'; select 2", "catalog"),
        Case.tainted("select id from orders where state = 'paid' -- billing report", "paid"),
        Case.of("select id from catalog -- describes information_schema in the manual"),
        Case.of("select table_name from information_schema.tables"),
        Case.tainted("select id from orders where id = 42 union select id from returns", "42"),
        Case.of("select id from invoices union /* archived */ all select id from archived_invoices"),
        Case.tainted("select 'union select' as title union select description from articles", "union select"),
        Case.tainted("select id from orders where state='OPEN' and 1=1", "OPEN"),
        Case.tainted("select id from orders where state='OPEN' or 1=0", "OPEN"),
        Case.tainted("select id from orders where state='PAID' or 1=1.5", "PAID"),
        Case.of("select id, name from users where status = 'active'"),
        Case.tainted("select * from orders where customer = 'O''Brien'", "O'Brien"),
        Case.of("select * from products where price between 100 and 200"),
        Case.tainted("update sessions set last_seen = now() where id = 42", "42"),
        Case.tainted("select * from logs where message like '%timeout%'", "timeout"),
        Case.tainted("select email from users where id = 1001", "1001"),
        Case.tainted("insert into audit(action, actor) values('login', 'alice')", "alice"),
        Case.tainted("select * from catalog where title = 'The Lord of the Rings'", "The Lord of the Rings"),
        Case.of("select count(*) from orders where created_at > now() - interval '1 day'"),
        Case.tainted("select * from cities where name = 'Côte d''Or'", "Côte d'Or"));
  }

  private static List<Case> commandCorpus() {
    return List.of(
        Case.tainted("printf %s O'Brien", "O'Brien"),
        Case.tainted("printf %s R&D", "R&D"),
        Case.tainted("printf %s Q1;Q2", "Q1;Q2"),
        Case.tainted("printf %s June|July", "June|July"),
        Case.of("echo curl http://probe.dnslog.cn/a"),
        Case.of("curl http://notdnslog.cn/report"),
        Case.of("curl https://reports.example.test/guide/dnslog.cn/a"),
        Case.of("curl -o probe.dnslog.cn https://reports.example.test/weekly"),
        Case.of("printf %s cat /etc/passwd"),
        Case.of("cat /etc/passwd.example"),
        Case.of("git status"),
        Case.of("/usr/bin/convert input.png output.jpg"),
        Case.of("ffmpeg -i input.mp4 -vcodec copy output.mp4"),
        Case.of("ls -la /var/app/data"),
        Case.tainted("python3 /opt/app/report.py --month 2026-05", "2026-05"),
        Case.of("tar czf backup.tgz /var/app/uploads"),
        Case.of("node /srv/app/index.js"),
        Case.of("/usr/bin/pdftoppm -png /tmp/in.pdf /tmp/out"));
  }

  private static List<Case> urlCorpus() {
    return List.of(
        Case.tainted("https://orders.example.test/api/orders/4981", "4981"),
        Case.tainted("https://search.example.test/?q=invoice", "invoice"),
        Case.of("http://10.2.3.4/actuator/health"),
        Case.of("http://127.0.0.1/ready"),
        Case.of("http://169.254.169.253/status"),
        Case.tainted("http://[fe80::a%25FloorA]/report", "http://[fe80::a%25floora]/report"),
        Case.of("http://127.0.0.1/admin/reports"),
        Case.tainted("http://10.0.0.5/admin/report-10", "10"),
        Case.tainted("https://reports.example.test/weekly", "https://reports.example.test/weekly"),
        Case.of("https://169.254.169.254.docs.example.test/reference"),
        Case.of("https://docs.example.test/latest/meta-data/guide"),
        Case.of("https://0xdocs.example.test/reference"),
        Case.of("https://notdnslog.cn/status"),
        Case.tainted("https://images.example.test/preview?src=https://cdn.example.test/image", "https://cdn.example.test/image"),
        Case.of("file:/srv/orders/lib/compiler.jar"),
        Case.of("file:/opt/orders/WEB-INF/templates.xml"),
        Case.tainted("file:/srv/orders/reports/4981.json", "4981"),
        Case.of("https://api.stripe.com/v1/charges"),
        Case.of("https://hooks.slack.com/services/T000/B000/abcdef"),
        Case.of("https://www.googleapis.com/oauth2/v3/certs"),
        Case.of("https://cdn.example.com/assets/logo.png"),
        Case.of("https://payments.partner.example.com/api/charge"),
        Case.of("https://graph.microsoft.com/v1.0/me"));
  }

  private static List<Case> fileReadCorpus() {
    return List.of(
        Case.of("/etc/ssl/certs/ca-certificates.crt"),
        Case.of("/proc/self/status"),
        Case.of("/srv/reports/snapshot/etc/passwd"),
        Case.tainted("/etc/hosts", "hosts"),
        Case.tainted("/srv/orders/4981.json", "4981"),
        Case.tainted("/srv/orders/4981.json", "/srv/orders/4981.json"),
        Case.tainted("/srv/reports/annual.csv", "/srv/reports/annual.csv"),
        Case.tainted("/srv/catalog/index", "/srv/catalog/index"),
        Case.tainted("/srv/reports/annual.csv", "annual.csv"),
        Case.tainted("/srv/images/drafts/../thumb.png", "drafts/../thumb.png"),
        Case.of("/var/app/uploads/photo.jpg"),
        Case.of("/opt/app/config/application.yml"),
        Case.of("/srv/data/reports/2026-05.csv"),
        Case.of("/home/appuser/.config/app/settings.json"),
        Case.of("/var/app/templates/invoice.html"));
  }

  private static List<Case> fileWriteCorpus() {
    return List.of(
        Case.of("/var/app/uploads/avatar-1001.png"),
        Case.of("/tmp/app-export-2026-05.csv"),
        Case.of("/srv/data/cache/thumb-42.jpg"),
        Case.of("weekly.txt::$DATA"),
        Case.of("index.txt::$INDEX"),
        Case.of("/var/app/logs/audit-2026-06-06.log"));
  }

  private static List<Case> deserializationCorpus() {
    return List.of(
        Case.of("java.util.ArrayList"),
        Case.of("java.lang.String"),
        Case.of("com.myapp.dto.OrderDto"),
        Case.of("java.time.Instant"),
        Case.of("java.util.LinkedHashMap"),
        Case.of("com.myapp.model.Customer"),
        Case.of("org.apache.commons.collections.functors.ChainedTransformer"),
        Case.of("org.apache.commons.collections.functors.ConstantTransformer"),
        Case.of("org.apache.commons.collections.functors.EqualPredicate"),
        Case.of("org.apache.commons.collections4.functors.ChainedTransformer"),
        Case.of("org.apache.commons.collections4.functors.ConstantTransformer"),
        Case.of("org.apache.commons.collections4.functors.EqualPredicate"),
        Case.of("javax.management.BadAttributeValueExpException"),
        Case.of("org.codehaus.groovy.runtime.GStringImpl"),
        Case.of("org.codehaus.groovy.runtime.NumberAwareComparator"),
        Case.of("org.apache.commons.beanutils.BasicDynaBean"),
        Case.of("org.apache.commons.beanutils.BasicDynaClass"),
        Case.of("org.apache.commons.beanutils.DynaProperty"));
  }

  private static List<Case> expressionCorpus() {
    return List.of(
        Case.of("#{user.displayName}"),
        Case.of("order.total > 100 ? 'priority' : 'standard'"),
        Case.of("items[0].price * quantity"),
        Case.of("customer.firstName + ' ' + customer.lastName"),
        Case.of("#{T(java.lang.Math).max(a, b)}"));
  }

  private static List<Case> jndiCorpus() {
    return List.of(
        Case.of("java:comp/env/jdbc/AppDataSource"),
        Case.of("java:comp/env/jms/QueueConnectionFactory"),
        Case.of("java:global/AppEjb/UserService"));
  }

  private static List<Case> dnsCorpus() {
    return List.of(
        Case.of("api.partner.example.com"),
        Case.of("db-primary.internal.example.com"),
        Case.of("notdnslog.cn"),
        Case.of("catalog.nonceye.io."),
        Case.of("smtp.example.com"),
        Case.of("storage.googleapis.com"));
  }

  private static List<Case> ognlCorpus() {
    // Legitimate Struts2/OGNL value expressions: property access, ValueStack
    // references, i18n lookups — none reference a dangerous class.
    return List.of(
        Case.of("user.name"),
        Case.of("#session.username"),
        Case.of("top.id"),
        Case.of("address.city"),
        Case.of("person.age > 18"),
        Case.of("%{getText('label.welcome')}"),
        Case.of("order.items.size()"));
  }

  private static List<Case> uploadCorpus() {
    // Ordinary user uploads: documents, images, archives of non-executable data.
    return List.of(
        Case.of("vacation-photo.jpg"),
        Case.of("Q2-report-2026.pdf"),
        Case.of("avatar.png"),
        Case.of("export-2026-06.csv"),
        Case.of("slides.pptx"),
        Case.of("resume.docx"));
  }

  private static List<Case> jdbcCorpus() {
    // Standard connection URLs across drivers; none request-controlled, none
    // using H2 INIT or MySQL connector deserialization parameters.
    return List.of(
        Case.of("jdbc:postgresql://db.internal:5432/app"),
        Case.of("jdbc:mysql://db.internal:3306/app?useSSL=true&serverTimezone=UTC"),
        Case.of("jdbc:h2:mem:testdb"),
        Case.of("jdbc:oracle:thin:@db.internal:1521:orcl"),
        Case.of("jdbc:sqlserver://db.internal;databaseName=app;encrypt=true"));
  }

  private static List<Case> requestParamCorpus() {
    // Ordinary text submitted to a search form, editor or documentation service.
    return List.of(
        Case.tainted("The <script> element is documented here.", "The <script> element is documented here."),
        Case.tainted("JavaScript: a reference guide", "JavaScript: a reference guide"),
        Case.tainted("I love <b>bold</b> and <i>italic</i> text", "I love <b>bold</b> and <i>italic</i> text"),
        Case.tainted("<p>Hello world</p>", "<p>Hello world</p>"),
        Case.tainted("<div class=\"card\">welcome home</div>", "<div class=\"card\">welcome home</div>"),
        Case.tainted("<ul><li>one</li><li>two</li></ul>", "<ul><li>one</li><li>two</li></ul>"),
        Case.tainted("prices: a < b, c > d", "prices: a < b, c > d"),
        Case.tainted("online surveys and onboarding tips", "online surveys and onboarding tips"));
  }

  private static List<Case> base64Corpus() {
    return List.of(
        Case.of("SGVsbG8sIHdvcmxkIQ=="),
        Case.of("A".repeat(64) + "AA=="),
        Case.of("A".repeat(65) + "A=="),
        Case.of("A".repeat(64) + "AAA="),
        Case.of("A".repeat(64) + "AAAA"),
        Case.tainted("A".repeat(64) + "AA==", "urlsafe"),
        Case.tainted("A".repeat(66), "urlsafe"),
        Case.tainted("A".repeat(64) + "A=\\nA=", "mime"));
  }

  private static String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() <= 80 ? value : value.substring(0, 77) + "...";
  }
}
