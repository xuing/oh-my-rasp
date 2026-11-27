package io.ohmyrasp.agent.http;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * What an event shows of a finding made on a request whose body the agent recorded, or whose parameters the
 * container parsed from a body, or of an operation carried from such a request: built from an allow-list, never
 * by taking body text out of what a rule wrote. Both engines build it the same way:
 * <ul>
 * <li>the rule id, category, action and hook as the rule set them, and a fixed message made from the rule id
 *     ({@link #fixedMessage});</li>
 * <li>the detail values of {@link #RULE_CONSTANTS}, which are a rule's own vocabulary;</li>
 * <li>for a finding that names the input it decided on (a request rule's {@code parameter}) or whose operand
 *     contains an input value (a sink rule that correlates request input), the name of that one input field cut
 *     to {@link #MAX_NAME_CHARS} characters ({@link #INPUT_FIELD}) and its value cut to {@link #MAX_VALUE_CHARS}
 *     ({@link #INPUT_VALUE}): the attacker's payload, which the attacker supplied;</li>
 * <li>every other detail (the command, SQL, path or URL as executed, a class name, a count) only as the hook's
 *     kind and the length of the longest one ({@link #OPERAND}, {@code "command, 37 chars"}).</li>
 * </ul>
 * No other field's name or value, no operand, no exception message and no part of the body's text is shown.
 */
public final class BodyEvidence {
  public static final int MAX_NAME_CHARS = 64;
  public static final int MAX_VALUE_CHARS = 256;
  public static final String INPUT_FIELD = "input_field";
  public static final String INPUT_VALUE = "input_value";
  public static final String OPERAND = "operand";
  /** The detail a request rule names the input it decided on with. */
  public static final String PARAMETER = "parameter";

  /** Detail keys whose values are a rule's own constants, never request text: shown as they are. */
  public static final Set<String> RULE_CONSTANTS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
      "decision_basis", "policy_basis", "process_operation", "argument_count", "multipart_source",
      "archive_policy_sha256", "kind")));

  private BodyEvidence() {}

  /** The message of a finding on such a request: the rule id and nothing a request can change. */
  public static String fixedMessage(String rule) {
    return "Rule " + (rule == null ? "" : rule) + " matched a request that has a body; its operands are withheld";
  }

  /**
   * The one input field a finding matched, as {name, value} cut, or null. {@code fields} are the request's
   * inputs (name to values: a String, a String[] or a collection of them); {@code parameter} the field a request
   * rule named, or null; {@code operands} the finding's other detail values. A named field is that field, with
   * the first of its values an operand contains (else its first value). Otherwise the field whose value of two
   * or more characters an operand contains, ignoring case, the longest such value first; else the first field
   * whose name of eight or more characters, with a character other than a letter, digit, '_' or '-', an operand
   * contains (the request input matching of the primary's {@code hasParameterIn}). Null when none.
   */
  public static String[] matched(Map<?, ?> fields, String parameter, Collection<String> operands) {
    String[] lowered = lowered(operands);
    if (parameter != null) {
      List<String> values = fields == null ? null : values(fields.get(parameter));
      String chosen = null;
      if (values != null) {
        for (String value : values) {
          if (value != null && value.length() >= 2 && within(value, lowered)) {
            chosen = value;
            break;
          }
        }
        if (chosen == null) {
          for (String value : values) {
            if (value != null && !value.isEmpty()) {
              chosen = value;
              break;
            }
          }
        }
      }
      return new String[] {cutName(parameter), chosen == null ? null : cutValue(chosen)};
    }
    if (fields == null || lowered.length == 0) return null;
    String bestName = null;
    String bestValue = null;
    for (Map.Entry<?, ?> field : fields.entrySet()) {
      for (String value : values(field.getValue())) {
        if (value == null || value.length() < 2 || (bestValue != null && value.length() <= bestValue.length())) continue;
        if (within(value, lowered)) {
          bestName = String.valueOf(field.getKey());
          bestValue = value;
        }
      }
    }
    if (bestValue != null) return new String[] {cutName(bestName), cutValue(bestValue)};
    for (Map.Entry<?, ?> field : fields.entrySet()) {
      String name = String.valueOf(field.getKey());
      if (significantName(name) && within(name, lowered)) {
        List<String> values = values(field.getValue());
        String first = values.isEmpty() ? null : values.get(0);
        return new String[] {cutName(name), first == null ? null : cutValue(first)};
      }
    }
    return null;
  }

  /** The operands as an event shows them: the hook's kind and the length of the longest, or null for none. */
  public static String operand(String kind, Collection<String> operands) {
    if (operands == null || operands.isEmpty()) return null;
    int longest = 0;
    for (String operand : operands) {
      if (operand != null) longest = Math.max(longest, operand.length());
    }
    return (kind == null || kind.isEmpty() ? "operand" : kind) + ", " + longest + " chars";
  }

  public static String cutName(String name) {
    return cut(name == null ? "" : name, MAX_NAME_CHARS);
  }

  public static String cutValue(String value) {
    return cut(value == null ? "" : value, MAX_VALUE_CHARS);
  }

  private static String cut(String text, int most) {
    if (text.length() <= most) return text;
    int end = most;
    if (Character.isHighSurrogate(text.charAt(end - 1))) end--;
    return text.substring(0, end);
  }

  private static String[] lowered(Collection<String> operands) {
    if (operands == null) return new String[0];
    String[] lowered = new String[operands.size()];
    int i = 0;
    for (String operand : operands) lowered[i++] = operand == null ? "" : operand.toLowerCase(Locale.ROOT);
    return lowered;
  }

  private static boolean within(String text, String[] lowered) {
    String needle = text.toLowerCase(Locale.ROOT);
    for (String operand : lowered) {
      if (operand.contains(needle)) return true;
    }
    return false;
  }

  private static boolean significantName(String name) {
    if (name == null || name.length() < 8) return false;
    for (int i = 0; i < name.length(); i++) {
      char ch = name.charAt(i);
      if (!Character.isLetterOrDigit(ch) && ch != '_' && ch != '-') return true;
    }
    return false;
  }

  /** The values of one input field, whatever the map holds for it. */
  @SuppressWarnings("unchecked")
  private static List<String> values(Object held) {
    if (held == null) return Collections.<String>emptyList();
    if (held instanceof String) return Collections.singletonList((String) held);
    if (held instanceof String[]) return Arrays.asList((String[]) held);
    if (held instanceof List<?>) {
      for (Object item : (List<?>) held) {
        if (item != null && !(item instanceof String)) return Collections.<String>emptyList();
      }
      return (List<String>) held;
    }
    return Collections.singletonList(String.valueOf(held));
  }
}
