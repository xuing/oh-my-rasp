package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.util.Map;
import java.util.Optional;

/** Guard for the JDK Base64 decoder tail-underflow candidate (CVE-2026-114938). */
public final class Base64DecodeDetector {
  private Base64DecodeDetector() {}

  public static boolean isBase64TailUnderflowCandidate(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME) {
    if (isMIME || src == null || sp < 0 || sl < sp || sl > src.length) {
      return false;
    }
    int length = sl - sp;
    if (length < 65) {
      return false;
    }
    int remainder = length & 63;
    if (remainder < 1 || remainder > 3) {
      return false;
    }
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    if (padding < 1 || padding > 2 || padding > remainder) {
      return false;
    }
    for (int i = sp; i < sl - padding; i++) {
      int c = src[i] & 0xff;
      if (!((c >= 'A' && c <= 'Z')
          || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9')
          || (isURL ? (c == '-' || c == '_') : (c == '+' || c == '/')))) {
        return false;
      }
    }
    return true;
  }

  public static Optional<Detection> detectBase64Decode(
      byte[] src, int sp, int sl, boolean isURL, boolean isMIME, RequestContext request) {
    if (!isBase64TailUnderflowCandidate(src, sp, sl, isURL, isMIME)) {
      return Optional.empty();
    }
    int length = sl - sp;
    int remainder = length & 63;
    int padding = 0;
    while (padding < 3 && src[sl - 1 - padding] == '=') {
      padding++;
    }
    return Optional.of(
        Detection.log(
            "base64",
            "base64_avx512_tail_underflow",
            99,
            "Base64.Decoder.decode0 rejected x64 AVX-512 tail-underflow candidate (CVE-2026-114938)",
            request,
            Map.of(
                "length", String.valueOf(length),
                "padding", String.valueOf(padding),
                "remainder", String.valueOf(remainder),
                "alphabet", isURL ? "URL-safe" : "standard",
                "cve", "CVE-2026-114938")));
  }
}
