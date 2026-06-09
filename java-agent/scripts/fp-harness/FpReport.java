import io.ohmyrasp.agent.detect.DetectorEngine;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;

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
        new Category("SQL queries", sqlCorpus(), (c, r) -> ENGINE.detectSql(c.payload(), r)),
        new Category("OS commands", commandCorpus(), (c, r) -> ENGINE.detectCommand(splitCommand(c.payload()), r)),
        new Category("Outbound URLs", urlCorpus(), (c, r) -> ENGINE.detectUrl(c.payload(), r)),
        new Category("File reads", fileReadCorpus(), (c, r) -> ENGINE.detectFileRead(c.payload(), r, false)),
        new Category("File writes", fileWriteCorpus(), (c, r) -> ENGINE.detectFileWrite(c.payload(), r)),
        new Category("Deserialization classes", deserializationCorpus(), (c, r) -> ENGINE.detectDeserialization(c.payload(), r)),
        new Category("Expressions", expressionCorpus(), (c, r) -> ENGINE.detectExpression("spel", c.payload(), r)),
        new Category("JNDI names", jndiCorpus(), (c, r) -> ENGINE.detectJndi(c.payload(), r)),
        new Category("DNS lookups", dnsCorpus(), (c, r) -> ENGINE.detectDns(c.payload(), r)));

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
        Case.of("https://api.stripe.com/v1/charges"),
        Case.of("https://hooks.slack.com/services/T000/B000/abcdef"),
        Case.of("https://www.googleapis.com/oauth2/v3/certs"),
        Case.of("https://cdn.example.com/assets/logo.png"),
        Case.of("https://payments.partner.example.com/api/charge"),
        Case.of("https://graph.microsoft.com/v1.0/me"));
  }

  private static List<Case> fileReadCorpus() {
    return List.of(
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
        Case.of("/var/app/logs/audit-2026-06-06.log"));
  }

  private static List<Case> deserializationCorpus() {
    return List.of(
        Case.of("java.util.ArrayList"),
        Case.of("java.lang.String"),
        Case.of("com.myapp.dto.OrderDto"),
        Case.of("java.time.Instant"),
        Case.of("java.util.LinkedHashMap"),
        Case.of("com.myapp.model.Customer"));
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
        Case.of("smtp.example.com"),
        Case.of("storage.googleapis.com"));
  }

  private static String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() <= 80 ? value : value.substring(0, 77) + "...";
  }
}
