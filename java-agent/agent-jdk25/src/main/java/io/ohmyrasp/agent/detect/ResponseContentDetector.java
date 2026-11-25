package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Response content: personal data in structured responses, and markup reflected from request input. */
public final class ResponseContentDetector {
  private ResponseContentDetector() {}

  // Syntax indicators for explicitly selected input policies and response observations.
  private static final Pattern XSS_INPUT =
      Pattern.compile(
          "(?is)<\\s*script\\b"
              + "|javascript\\s*:"
              + "|\\bon(?:error|load|click|dblclick|mouse[a-z]*|key[a-z]*|focus[a-z]*|blur"
              + "|change|submit|reset|select|input|toggle|scroll|wheel|contextmenu"
              + "|copy|cut|paste|drag[a-z]*|drop|animation[a-z]*|transition[a-z]*"
              + "|pointer[a-z]*|play[a-z]*|abort|unload|resize|show|begin|finish"
              + "|pageshow|pagehide|hashchange|popstate|message|storage|beforescriptexecute)"
              + "\\s*=");

  private static final Pattern STRUCTURED_RESPONSE = Pattern.compile(
      "(?i)(?:text/html|(?:application|text)/(?:json|xml)|[a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+\\+(?:json|xml))");

  private static final Pattern CHINA_ID =
      Pattern.compile("(?<!\\d)\\d{10}(?:[01]\\d)(?:[0123]\\d)\\d{3}(?:\\d|x|X)(?!\\d)");

  private static final Pattern CHINA_MOBILE =
      Pattern.compile("(?<!\\w)(?:(?:00|\\+)?86 ?)?(1\\d{2})(?:[ -]?\\d){8}(?!\\w)");

  private static final Pattern BANK_CARD =
      Pattern.compile("(?<!\\d)(?:62|3|5[1-5]|4\\d)\\d{2}(?:[ -]?\\d{4}){3}(?!\\d)");

  private static final Set<String> CHINA_MOBILE_PREFIXES =
      Set.of(
          "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "145",
          "146", "147", "148", "149", "150", "151", "152", "153", "155", "156", "157",
          "158", "159", "165", "166", "170", "173", "174", "175", "176", "177", "178",
          "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "198",
          "199");

  public static Optional<Detection> detectMarkupParameter(RequestContext request) {
    for (String value : request.allParameterValues()) {
      if (value != null && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "request",
                "xss_userinput",
                70,
                "XSS-like request parameter detected",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectResponseDataLeak(
      String contentType, String content, RequestContext request) {
    if (contentType == null || content == null) return Optional.empty();
    int separator = contentType.indexOf(';');
    String mediaType = (separator < 0 ? contentType : contentType.substring(0, separator)).trim();
    if (!STRUCTURED_RESPONSE.matcher(mediaType).matches()) return Optional.empty();
    Optional<String> identityCard = firstValidIdentityCard(content);
    if (identityCard.isPresent()) {
      return dataLeak("Identity Card", identityCard.orElseThrow(), request);
    }
    Optional<String> mobileNumber = firstValidMobileNumber(content);
    if (mobileNumber.isPresent()) {
      return dataLeak("Mobile Number", mobileNumber.orElseThrow(), request);
    }
    Optional<String> bankCard = firstValidBankCard(content);
    if (bankCard.isPresent()) {
      return dataLeak("Bank Card", bankCard.orElseThrow(), request);
    }
    return Optional.empty();
  }

  public static Optional<Detection> detectXssEcho(String content, RequestContext request) {
    if (content == null || content.isBlank()) {
      return Optional.empty();
    }
    for (String value : request.allParameterValues()) {
      if (value != null && !value.isBlank() && content.contains(value) && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "response",
                "xss_echo",
                70,
                "Response echoes XSS-like request input",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  private static Optional<Detection> dataLeak(
      String kind, String matchedValue, RequestContext request) {
    return Optional.of(
        Detection.log(
            "response",
            "response_dataLeak",
            80,
            "PII leak detected: " + kind,
            request,
            Map.of("kind", kind, "match", matchedValue)));
  }

  private static Optional<String> firstValidIdentityCard(String content) {
    var matcher = CHINA_ID.matcher(content);
    int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    while (matcher.find()) {
      String id = matcher.group();
      if (id.charAt(0) == '0') {
        continue;
      }
      int sum = 0;
      for (int i = 0; i < weights.length; i++) {
        sum += Character.digit(id.charAt(i), 10) * weights[i];
      }
      char check = id.charAt(17);
      sum += (check == 'X' || check == 'x') ? 10 : Character.digit(check, 10);
      if (sum % 11 == 1) {
        return Optional.of(id);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidMobileNumber(String content) {
    var matcher = CHINA_MOBILE.matcher(content);
    while (matcher.find()) {
      if (CHINA_MOBILE_PREFIXES.contains(matcher.group(1))) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidBankCard(String content) {
    var matcher = BANK_CARD.matcher(content);
    while (matcher.find()) {
      String card = matcher.group().replace(" ", "").replace("-", "");
      if (luhn(card)) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static boolean luhn(String digits) {
    int sum = 0;
    boolean doubleDigit = false;
    for (int i = digits.length() - 1; i >= 0; i--) {
      int value = Character.digit(digits.charAt(i), 10);
      if (value < 0) {
        return false;
      }
      if (doubleDigit) {
        value *= 2;
      }
      sum += value / 10 + value % 10;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 == 0;
  }
}
