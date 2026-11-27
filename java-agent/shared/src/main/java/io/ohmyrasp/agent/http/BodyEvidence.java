package io.ohmyrasp.agent.http;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Takes the text of a request body out of what leaves a rule: the detail values, the message and anything else
 * an event, a log line, an exception or telemetry would carry. A rule decides on the body's values; what it
 * reports names the body field the evidence came from, never the field's value or a fragment of the body.
 * For one text ({@link #scrub}):
 * <ul>
 * <li>a text that is a body field's name (a JSON key, or a form name that is not also a request parameter), or a
 *     part of one at least {@link #MIN_FRAGMENT_CHARS} long, becomes {@code body:<name>}, cut to
 *     {@link #MAX_NAME_CHARS} characters;</li>
 * <li>a text that is a body value, a part of one at least {@link #MIN_VALUE_FRAGMENT_CHARS} long, or a part of
 *     the body's text at least {@link #MIN_FRAGMENT_CHARS} long, becomes {@code [body:<field>]} ({@code [body]}
 *     for text of no field);</li>
 * <li>in any other text (a command, an SQL statement, a path or URL that a sink assembled, a rule's composite
 *     detail): each body value at least {@link #MIN_EMBEDDED_CHARS} long is replaced by {@code [body:<field>]},
 *     then, where no value was, each body name that long by {@code body:<name>} cut, and then every run of text
 *     that still matches a body value over at least {@link #MIN_VALUE_FRAGMENT_CHARS} characters, or the body's
 *     text over at least {@link #MIN_FRAGMENT_CHARS}, by {@code [body]}.</li>
 * </ul>
 * A value shorter than {@link #MIN_EMBEDDED_CHARS} inside a longer text is not replaced: one or two characters
 * cannot be told from the text's own. Text equal to one of {@code kept} (the request's own method, URI and query,
 * which an event carries anyway) is left as it is, and so are the values of {@link #RULE_CONSTANTS}, which the
 * engines do not pass here.
 *
 * <p>Cost: only a finding made while a body is recorded is scrubbed. The body's 8-character fragments are
 * hashed once per scrubber (at most {@link RequestBody#MAX_UNITS} of them), then each text costs a pass per body
 * value and name and one hash lookup per character.
 */
public final class BodyEvidence {
  public static final int MAX_NAME_CHARS = 64;
  public static final int MIN_EMBEDDED_CHARS = 3;
  public static final int MIN_FRAGMENT_CHARS = 8;
  public static final int MIN_VALUE_FRAGMENT_CHARS = 4;

  /** Detail keys whose values are a rule's own constants, never request text: left as they are. */
  public static final Set<String> RULE_CONSTANTS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
      "decision_basis", "policy_basis", "process_operation", "argument_count", "multipart_source",
      "archive_policy_sha256", "method")));

  // A nested class, not a lambda: backport hooks reach this.
  private static final Comparator<int[]> BY_START_THEN_LONGEST = new Comparator<int[]>() {
    @Override public int compare(int[] left, int[] right) {
      if (left[0] != right[0]) return left[0] - right[0];
      return (right[1] - right[0]) - (left[1] - left[0]);
    }
  };

  private final RequestBodySnapshot body;
  private final Collection<String> requestNames;
  private final Collection<String> kept;
  private Set<String> fragments;
  private Set<String> valueFragments;

  private BodyEvidence(RequestBodySnapshot body, Collection<String> requestNames, Collection<String> kept) {
    this.body = body;
    this.requestNames = requestNames == null ? Collections.<String>emptySet() : requestNames;
    this.kept = kept == null ? Collections.<String>emptySet() : kept;
  }

  /**
   * A scrubber for texts of one finding made while {@code body} was recorded. {@code requestNames} are the
   * request's own parameter names (a body name equal to one is not marked); {@code kept} texts are left alone.
   */
  public static BodyEvidence of(RequestBodySnapshot body, Collection<String> requestNames, Collection<String> kept) {
    return new BodyEvidence(body, requestNames, kept);
  }

  /** {@link #scrub(String)} with a scrubber of its own. */
  public static String scrub(String text, RequestBodySnapshot body, Collection<String> requestNames,
      Collection<String> kept) {
    return body == null ? text : of(body, requestNames, kept).scrub(text);
  }

  /** How an event names a body field: {@code body:} and the name, cut. */
  public static String fieldName(String name) {
    return "body:" + cut(name == null ? "" : name);
  }

  /** The marker that stands where a body value was. */
  public static String marker(String field) {
    return field == null || field.isEmpty() ? "[body]" : "[body:" + cut(field) + "]";
  }

  /**
   * A rule's message without the body's text: as {@link #scrub}, but pieces shorter than
   * {@link #MIN_FRAGMENT_CHARS} are not matched against the body's values, so that the rule's own words (which
   * share four letters with many values) stay readable.
   */
  public String scrubMessage(String text) {
    return scrub(text, false);
  }

  /** {@code text} without the body's text, as described above; {@code text} itself when it holds none. */
  public String scrub(String text) {
    return scrub(text, true);
  }

  private String scrub(String text, boolean valuePieces) {
    if (text == null || text.isEmpty() || kept.contains(text)) return text;
    BodyValues values = body.values();
    Map<String, List<String>> fields = values.parameters();
    for (String name : values.names()) {
      if (name.isEmpty() || requestNames.contains(name)) continue;
      if (text.equals(name)) return fieldName(name);
      if (text.length() >= MIN_FRAGMENT_CHARS && name.contains(text)) return fieldName(text);
    }
    for (Map.Entry<String, List<String>> field : fields.entrySet()) {
      for (String value : field.getValue()) {
        if (value.isEmpty()) continue;
        if (text.equals(value)) return marker(field.getKey());
        if (text.length() >= MIN_VALUE_FRAGMENT_CHARS && value.contains(text)) return marker(field.getKey());
      }
    }
    if (text.length() >= MIN_FRAGMENT_CHARS && body.text().contains(text)) return marker(null);
    return scrubInside(text, values, fields, valuePieces);
  }

  /** Replaces the body's values, long names and remaining fragments inside a longer text. */
  private String scrubInside(String text, BodyValues values, Map<String, List<String>> fields, boolean valuePieces) {
    // Intervals [start, end, index into replacements]: the values first, then names where no value is.
    List<String> replacements = new ArrayList<String>();
    List<int[]> valueIntervals = new ArrayList<int[]>();
    for (Map.Entry<String, List<String>> field : fields.entrySet()) {
      for (String value : field.getValue()) {
        if (value.length() >= MIN_EMBEDDED_CHARS) {
          occurrences(text, value, marker(field.getKey()), valueIntervals, replacements);
        }
      }
    }
    List<int[]> nameIntervals = new ArrayList<int[]>();
    for (String name : values.names()) {
      if (name.length() >= MIN_EMBEDDED_CHARS && !requestNames.contains(name)) {
        occurrences(text, name, fieldName(name), nameIntervals, replacements);
      }
    }
    boolean[] covered = new boolean[text.length()];
    List<int[]> taken = new ArrayList<int[]>();
    take(valueIntervals, covered, taken);
    take(nameIntervals, covered, taken);
    // What is left that still matches a body value over MIN_VALUE_FRAGMENT_CHARS characters, or the body's
    // text (keys and syntax included) over MIN_FRAGMENT_CHARS.
    boolean[] fragment = new boolean[text.length()];
    if (valuePieces) mark(text, valueFragments(), MIN_VALUE_FRAGMENT_CHARS, covered, fragment);
    mark(text, fragments(), MIN_FRAGMENT_CHARS, covered, fragment);
    if (taken.isEmpty()) {
      boolean any = false;
      for (boolean f : fragment) any |= f;
      if (!any) return text;
    }
    StringBuilder out = new StringBuilder(text.length());
    int next = 0; // the next taken interval
    Collections.sort(taken, BY_START_THEN_LONGEST);
    for (int i = 0; i < text.length();) {
      if (next < taken.size() && taken.get(next)[0] == i) {
        out.append(replacements.get(taken.get(next)[2]));
        i = taken.get(next)[1];
        next++;
      } else if (fragment[i]) {
        out.append(marker(null));
        while (i < text.length() && fragment[i]) i++;
      } else {
        out.append(text.charAt(i));
        i++;
      }
    }
    return out.toString();
  }

  /** Takes the earliest, longest of {@code intervals} that overlap nothing taken yet. */
  private static void take(List<int[]> intervals, boolean[] covered, List<int[]> taken) {
    Collections.sort(intervals, BY_START_THEN_LONGEST);
    for (int[] interval : intervals) {
      boolean free = true;
      for (int i = interval[0]; i < interval[1] && free; i++) free = !covered[i];
      if (!free) continue;
      for (int i = interval[0]; i < interval[1]; i++) covered[i] = true;
      taken.add(interval);
    }
  }

  private static void occurrences(String text, String part, String replacement, List<int[]> found,
      List<String> replacements) {
    int at = text.indexOf(part);
    if (at < 0) return;
    int index = replacements.size();
    replacements.add(replacement);
    while (at >= 0) {
      found.add(new int[] {at, at + part.length(), index});
      at = text.indexOf(part, at + part.length());
    }
  }

  private static void mark(String text, Set<String> grams, int size, boolean[] covered, boolean[] fragment) {
    for (int i = 0; i + size <= text.length(); i++) {
      if (grams.contains(text.substring(i, i + size))) {
        for (int j = i; j < i + size; j++) if (!covered[j]) fragment[j] = true;
      }
    }
  }

  /** Every MIN_VALUE_FRAGMENT_CHARS-character piece of the body's values, made once per scrubber. */
  private Set<String> valueFragments() {
    Set<String> grams = valueFragments;
    if (grams != null) return grams;
    grams = new HashSet<String>();
    for (String value : body.values().values()) {
      for (int i = 0; i + MIN_VALUE_FRAGMENT_CHARS <= value.length(); i++) {
        grams.add(value.substring(i, i + MIN_VALUE_FRAGMENT_CHARS));
      }
    }
    valueFragments = grams;
    return grams;
  }

  /** Every MIN_FRAGMENT_CHARS-character piece of the body's text, made once per scrubber. */
  private Set<String> fragments() {
    Set<String> grams = fragments;
    if (grams != null) return grams;
    String raw = body.text();
    grams = new HashSet<String>(Math.max(16, raw.length() * 2));
    for (int i = 0; i + MIN_FRAGMENT_CHARS <= raw.length(); i++) grams.add(raw.substring(i, i + MIN_FRAGMENT_CHARS));
    fragments = grams;
    return grams;
  }

  private static String cut(String name) {
    if (name.length() <= MAX_NAME_CHARS) return name;
    int end = MAX_NAME_CHARS;
    if (Character.isHighSurrogate(name.charAt(end - 1))) end--;
    return name.substring(0, end) + "...";
  }
}
