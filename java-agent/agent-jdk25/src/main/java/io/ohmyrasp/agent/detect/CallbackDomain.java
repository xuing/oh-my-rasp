package io.ohmyrasp.agent.detect;

import java.util.regex.Pattern;

/** Domain policy shared by DNS, HTTP and direct process destinations. */
final class CallbackDomain {
  private static final Pattern DNSLOG_DOMAIN =
      Pattern.compile(
          "(?i)(?:[a-z0-9_-]+\\.)*((?:ceye|exeye|sslip|nip)\\.io|dnslog\\.cn|(?:vcap|bxss)\\.me|xip\\.(?:name|io)|burpcollaborator\\.net|tu4\\.org|2xss\\.cc|request\\.bin|requestbin\\.net|pipedream\\.net|canarytokens\\.com)$");

  private CallbackDomain() {}

  static boolean matches(String normalizedHost) {
    return normalizedHost.length() <= 253 && DNSLOG_DOMAIN.matcher(normalizedHost).matches();
  }
}
