package io.ohmyrasp.agent.rules;

import java.util.Locale;

/**
 * Whether a finding made on a thread that is not serving an HTTP request blocks, on every agent line.
 *
 * <p>Outside a request (a scheduled job, a message consumer, a background thread, start-up code) every line blocks
 * a finding in block mode, as it does inside one, unless the operator turns that into "log only": the finding is
 * then recorded with the action {@code log} and the operation runs. Inside a request nothing changes. The setting
 * is the control document's top-level {@value #CONTROL_KEY} member, or for a standalone agent the agent argument
 * {@value #CONTROL_KEY}, the system property {@value #PROPERTY}, the environment variable {@value #ENVIRONMENT} or
 * the baked {@value #CONTROL_KEY} of {@code META-INF/ohmyrasp-shirudo.properties}, resolved like {@code mode}.
 *
 * <p>Java 8 source with no lambdas: the backport lines read it from their hooks.
 */
public final class OutsideRequest {
  /** The member of the control document, the agent argument and the baked property. */
  public static final String CONTROL_KEY = "outside_request";
  /** The system property. */
  public static final String PROPERTY = "ohmyrasp.outside_request";
  /** The environment variable. */
  public static final String ENVIRONMENT = "OHMYRASP_OUTSIDE_REQUEST";
  /** Without a setting a finding outside a request blocks, as the backport lines always did. */
  public static final boolean DEFAULT_BLOCKS = true;

  /**
   * Rules that block only inside a request, on every line that has them: outside one they log whatever the setting
   * says, because what they match is too broad to block without a request that supplied it. Each id is a primary
   * rule id, or a backport family without the line prefix. docs/detection.md says why each is here.
   *
   * <ul>
   *   <li>{@code ssrf_obfuscate}: it also reports any URL that {@code java.net.URI} cannot parse, such as a file
   *       or JAR location with a space in it, which class loading and resource lookups open at start-up.
   *   <li>{@code ssrf_protocol}: a scheduled job fetches an {@code ftp:} or {@code ldap:} URL on purpose.
   * </ul>
   */
  private static final String[] REQUEST_ONLY = {"ssrf_obfuscate", "ssrf_protocol"};

  private OutsideRequest() {}

  /**
   * Whether a finding of {@code rule} (a primary rule id, or a backport family without the line prefix) may block
   * outside a request; false for the rules that block only inside one.
   */
  public static boolean mayBlockOutsideRequest(String rule) {
    if (rule == null) {
      return true;
    }
    for (int i = 0; i < REQUEST_ONLY.length; i++) {
      if (REQUEST_ONLY[i].equals(rule)) {
        return false;
      }
    }
    return true;
  }

  /**
   * {@code TRUE} for {@code block}, {@code FALSE} for {@code log}, null for anything else. Letter case is ignored,
   * and so are characters up to U+0020 around the word, as for {@code mode}.
   */
  public static Boolean parse(String token) {
    if (token == null) {
      return null;
    }
    String value = token.trim().toLowerCase(Locale.ROOT);
    if (value.equals("block")) {
      return Boolean.TRUE;
    }
    if (value.equals("log")) {
      return Boolean.FALSE;
    }
    return null;
  }
}
