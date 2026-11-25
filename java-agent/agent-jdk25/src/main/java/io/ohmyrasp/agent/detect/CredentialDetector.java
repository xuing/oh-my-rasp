package io.ohmyrasp.agent.detect;

import static io.ohmyrasp.agent.detect.DetectorStrings.abbreviate;
import static io.ohmyrasp.agent.detect.DetectorStrings.lower;
import static io.ohmyrasp.agent.detect.DetectorStrings.normalizeParameterName;
import static io.ohmyrasp.agent.detect.DetectorStrings.percentDecode;
import static io.ohmyrasp.agent.detect.RequestValues.firstNonBlankParameter;
import static io.ohmyrasp.agent.detect.SerializedRequestState.startsWithJavaSerializationStream;
import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Credential, signed-token and cookie evidence, with the redaction for each finding. */
final class CredentialDetector {
  private CredentialDetector() {}

  private static final Pattern JWT_HMAC_ALGORITHM =
      Pattern.compile("\"alg\"\\s*:\\s*\"(HS(?:256|384|512))\"");

  private static final Pattern COMPACT_JWT =
      Pattern.compile("(?is)^[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{6,}$");

  private static final Pattern JWT_VERIFICATION_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:api|de2api|auth|token|tokens|admin|console|manage|management|user|users|datasource|dashboard|system|settings)(?:[;/]|/|$)");

  private static final Pattern EMPTY_CREDENTIAL_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:webtools|control|admin|admins|console|manage|management|account|accounts|user|users)(?:[;/]|/|$)");

  private static final Pattern DEFAULT_CREDENTIAL_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|console|manager|host-manager|manage|management|api|jolokia|login|cas|oauth|securityrealm|webtools|accounting)(?:[;/]|/|$)");

  private static final Set<String> EMPTY_CREDENTIAL_USERNAME_PARAMETERS =
      Set.of("username", "user", "userid", "login", "loginid", "account");

  private static final Set<String> EMPTY_CREDENTIAL_PASSWORD_PARAMETERS =
      Set.of("password", "passwd", "pwd", "pass");

  private static final Set<String> EMPTY_CREDENTIAL_BYPASS_PARAMETERS =
      Set.of(
          "requirepasswordchange",
          "passwordchange",
          "changepassword",
          "forcepasswordchange",
          "externalloginkey",
          "securitygroupid");

  private static final Set<String> DEFAULT_CREDENTIAL_USERNAME_PARAMETERS =
      Set.of("username", "user", "userid", "login", "loginid", "account", "jusername");

  private static final Set<String> DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS =
      Set.of("password", "passwd", "pwd", "pass", "jpassword");

  private static final Map<String, String> DEFAULT_JWT_HMAC_SECRETS =
      Map.of("hugegraph-default-token-secret", "FXQXbJtbCLxODc6tGci732pkH1cyf8Qg");

  private static final Set<String> DEFAULT_ENCRYPTED_COOKIE_NAMES = Set.of("rememberme");

  private static final Map<String, String> DEFAULT_COOKIE_AES_KEYS =
      Map.of("shiro-default-aes-key", "kPH+bIxk5D2deZiIxcaaaA==");

  private static final Map<String, String> DEFAULT_CREDENTIAL_PAIRS =
      Map.ofEntries(
          Map.entry("admin\nadmin", "activemq-admin-default"),
          Map.entry("tomcat\ntomcat", "tomcat-manager-default"),
          Map.entry("weblogic\noracle@123", "weblogic-lab-default"),
          Map.entry("weblogic\nweblogic", "weblogic-common-default"),
          Map.entry("admin\nvulhub", "jenkins-lab-default"));

  static Optional<Detection> defaultSignedTokenFinding(RequestContext request) {
    Optional<JwtDefaultSecretMatch> defaultJwt = defaultJwtSecretMatch(request);
    if (defaultJwt.isPresent()) {
      JwtDefaultSecretMatch match = defaultJwt.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_default_jwt_secret",
              95,
              "Bearer JWT is signed with a known default HMAC secret",
              request,
              Map.of(
                  "keyId", match.keyId(),
                  "algorithm", match.algorithm(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> defaultEncryptedCookieFinding(RequestContext request) {
    Optional<DefaultEncryptedCookieMatch> defaultCookie = defaultEncryptedCookieMatch(request);
    if (defaultCookie.isPresent()) {
      DefaultEncryptedCookieMatch match = defaultCookie.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_default_crypto_cookie",
              95,
              "Encrypted cookie contains a Java object stream under a known default key",
              request,
              Map.of(
                  "cookieName", match.cookieName(),
                  "keyId", match.keyId(),
                  "cipher", match.cipher(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> defaultCredentialFinding(RequestContext request) {
    Optional<DefaultCredentialMatch> defaultCredential = defaultCredentialAttempt(request);
    if (defaultCredential.isPresent()) {
      DefaultCredentialMatch match = defaultCredential.orElseThrow();
      RequestContext redactedRequest = redactCredentialRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_default_credential",
              88,
              "Request uses a known default administrative credential on a control path",
              redactedRequest,
              Map.of(
                  "credentialId", match.credentialId(),
                  "mechanism", match.mechanism(),
                  "username", match.username(),
                  "usernameSource", match.usernameSource(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> emptyCredentialFinding(RequestContext request) {
    Optional<EmptyCredentialBypassMatch> emptyCredentials = emptyCredentialBypass(request);
    if (emptyCredentials.isPresent()) {
      EmptyCredentialBypassMatch match = emptyCredentials.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_empty_credential_bypass",
              90,
              "Request attempts control access with empty credentials and a bypass flag",
              request,
              Map.of(
                  "usernameParameter", match.usernameParameter(),
                  "passwordParameter", match.passwordParameter(),
                  "bypassParameter", match.bypassParameter(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    return Optional.empty();
  }

  static Optional<Detection> detectJwtVerificationFailure(
      String mechanism, String exceptionClass, String message, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active() || !jwtVerificationFailureType(exceptionClass)) {
      return Optional.empty();
    }
    Optional<JwtTokenSource> tokenSource = jwtTokenSource(safeRequest);
    if (tokenSource.isEmpty() || !jwtVerificationRequestContext(safeRequest, tokenSource.orElseThrow())) {
      return Optional.empty();
    }
    String hook = mechanism == null || mechanism.isBlank() ? "jwt" : mechanism;
    RequestContext redactedRequest =
        redactJwtTokenRequest(safeRequest, tokenSource.orElseThrow().source());
    return Optional.of(
        Detection.log(
            "request",
            "request_jwt_verification_failure",
            95,
            "JWT verification failed during request authentication",
            redactedRequest,
            Map.of(
                "mechanism", abbreviate(hook),
                "decision_basis", "synthetic_verifier_failure",
                "exception", abbreviate(exceptionClass),
                "tokenSource", tokenSource.orElseThrow().source(),
                "method", redactedRequest.method(),
                "uri", abbreviate(redactedRequest.uri()))));
  }

  private record JwtDefaultSecretMatch(String keyId, String algorithm) {}

  private record DefaultEncryptedCookieMatch(String cookieName, String keyId, String cipher) {}

  private record DefaultCredentialMatch(
      String credentialId, String mechanism, String username, String usernameSource) {}

  private record EmptyCredentialBypassMatch(
      String usernameParameter, String passwordParameter, String bypassParameter) {}

  private record JwtTokenSource(String source, String token) {}

  private static boolean jwtVerificationFailureType(String exceptionClass) {
    return "com.auth0.jwt.exceptions.SignatureVerificationException".equals(exceptionClass)
        || "com.auth0.jwt.exceptions.AlgorithmMismatchException".equals(exceptionClass);
  }

  private static Optional<JwtTokenSource> jwtTokenSource(RequestContext request) {
    Optional<String> authorization = request.header("authorization").map(String::trim);
    if (authorization.isPresent()
        && authorization.orElseThrow().regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      String token = authorization.orElseThrow().substring("Bearer ".length()).trim();
      if (COMPACT_JWT.matcher(token).matches()) {
        return Optional.of(new JwtTokenSource("authorization", token));
      }
    }
    for (String header : List.of("x-de-token", "x-auth-token", "x-access-token", "x-jwt-token")) {
      String token = request.header(header).orElse("").trim();
      if (COMPACT_JWT.matcher(token).matches()) {
        return Optional.of(new JwtTokenSource(header, token));
      }
    }
    return Optional.empty();
  }

  private static boolean jwtVerificationRequestContext(
      RequestContext request, JwtTokenSource tokenSource) {
    String uri = request.uri();
    if (JWT_VERIFICATION_CONTROL_PATH.matcher(uri).find()) {
      return true;
    }
    return "x-de-token".equals(tokenSource.source()) && lower(uri).contains("/de2api/");
  }

  private static RequestContext redactJwtTokenRequest(RequestContext request, String tokenSource) {
    if (request == null) {
      return RequestContext.empty();
    }
    var headers = new LinkedHashMap<>(request.headers());
    if ("authorization".equals(tokenSource)) {
      headers.put("authorization", "Bearer [redacted]");
    } else if (headers.containsKey(tokenSource)) {
      headers.put(tokenSource, "[redacted]");
    }
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), headers, request.body());
  }

  private static Optional<JwtDefaultSecretMatch> defaultJwtSecretMatch(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String authorization = request.header("authorization").orElse("").trim();
    if (!authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      return Optional.empty();
    }
    String token = authorization.substring("Bearer ".length()).trim();
    if (token.isBlank() || token.length() > 8192) {
      return Optional.empty();
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
      return Optional.empty();
    }
    String algorithm = jwtHmacAlgorithm(parts[0]).orElse("");
    if (algorithm.isBlank()) {
      return Optional.empty();
    }
    String signingInput = parts[0] + "." + parts[1];
    byte[] signature;
    try {
      signature = Base64.getUrlDecoder().decode(parts[2]);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> secret : DEFAULT_JWT_HMAC_SECRETS.entrySet()) {
      Optional<byte[]> expected = jwtHmac(signingInput, algorithm, secret.getValue());
      if (expected.isPresent() && MessageDigest.isEqual(signature, expected.orElseThrow())) {
        return Optional.of(new JwtDefaultSecretMatch(secret.getKey(), algorithm));
      }
    }
    return Optional.empty();
  }

  private static Optional<DefaultEncryptedCookieMatch> defaultEncryptedCookieMatch(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String cookieHeader = request.header("cookie").orElse("");
    if (cookieHeader.isBlank() || cookieHeader.length() > 8192) {
      return Optional.empty();
    }
    for (String cookie : cookieHeader.split(";")) {
      int separator = cookie.indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = cookie.substring(0, separator).trim();
      String normalizedName = name.toLowerCase(Locale.ROOT);
      if (!DEFAULT_ENCRYPTED_COOKIE_NAMES.contains(normalizedName)) {
        continue;
      }
      String value = percentDecode(cookie.substring(separator + 1).trim());
      if (value.isBlank() || value.length() > 4096) {
        continue;
      }
      Optional<byte[]> encrypted = base64DecodeCookie(value);
      if (encrypted.isEmpty() || encrypted.orElseThrow().length < 32) {
        continue;
      }
      byte[] bytes = encrypted.orElseThrow();
      if ((bytes.length - 16) % 16 != 0) {
        continue;
      }
      for (Map.Entry<String, String> key : DEFAULT_COOKIE_AES_KEYS.entrySet()) {
        Optional<byte[]> plaintext = aesCbcPkcs5Decrypt(bytes, key.getValue());
        if (plaintext.isPresent() && startsWithJavaSerializationStream(plaintext.orElseThrow())) {
          return Optional.of(
              new DefaultEncryptedCookieMatch(name, key.getKey(), "AES/CBC/PKCS5Padding"));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<byte[]> base64DecodeCookie(String value) {
    try {
      return Optional.of(Base64.getDecoder().decode(value));
    } catch (IllegalArgumentException e) {
      try {
        return Optional.of(Base64.getUrlDecoder().decode(value));
      } catch (IllegalArgumentException ignored) {
        return Optional.empty();
      }
    }
  }

  private static Optional<byte[]> aesCbcPkcs5Decrypt(byte[] ivAndCiphertext, String keyBase64) {
    try {
      byte[] key = Base64.getDecoder().decode(keyBase64);
      byte[] iv = new byte[16];
      byte[] ciphertext = new byte[ivAndCiphertext.length - 16];
      System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);
      System.arraycopy(ivAndCiphertext, 16, ciphertext, 0, ciphertext.length);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
      return Optional.of(cipher.doFinal(ciphertext));
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      return Optional.empty();
    }
  }

  private static Optional<DefaultCredentialMatch> defaultCredentialAttempt(
      RequestContext request) {
    if (request == null || !request.active() || !defaultCredentialControlContext(request)) {
      return Optional.empty();
    }
    Optional<DefaultCredentialMatch> basic = defaultBasicCredential(request);
    if (basic.isPresent()) {
      return basic;
    }
    Optional<Map.Entry<String, String>> username =
        firstNonBlankParameter(request.parameters(), DEFAULT_CREDENTIAL_USERNAME_PARAMETERS);
    Optional<Map.Entry<String, String>> password =
        firstNonBlankParameter(request.parameters(), DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS);
    if (username.isEmpty() || password.isEmpty()) {
      return Optional.empty();
    }
    return defaultCredentialMatch(
        username.orElseThrow().getValue(),
        password.orElseThrow().getValue(),
        "form",
        username.orElseThrow().getKey());
  }

  private static Optional<DefaultCredentialMatch> defaultBasicCredential(RequestContext request) {
    String authorization = request.header("authorization").orElse("").trim();
    if (!authorization.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
      return Optional.empty();
    }
    String encoded = authorization.substring("Basic ".length()).trim();
    if (encoded.isBlank() || encoded.length() > 2048) {
      return Optional.empty();
    }
    String decoded;
    try {
      decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    int separator = decoded.indexOf(':');
    if (separator <= 0) {
      return Optional.empty();
    }
    return defaultCredentialMatch(
        decoded.substring(0, separator), decoded.substring(separator + 1), "basic", "authorization");
  }

  private static Optional<DefaultCredentialMatch> defaultCredentialMatch(
      String username, String password, String mechanism, String usernameSource) {
    if (username == null || password == null) {
      return Optional.empty();
    }
    String normalizedUsername = username.trim().toLowerCase(Locale.ROOT);
    String normalizedPassword = password.trim().toLowerCase(Locale.ROOT);
    if (normalizedUsername.isBlank() || normalizedPassword.isBlank()) {
      return Optional.empty();
    }
    String credentialId = DEFAULT_CREDENTIAL_PAIRS.get(normalizedUsername + "\n" + normalizedPassword);
    if (credentialId == null) {
      return Optional.empty();
    }
    return Optional.of(
        new DefaultCredentialMatch(credentialId, mechanism, normalizedUsername, usernameSource));
  }

  private static boolean defaultCredentialControlContext(RequestContext request) {
    String uri = request.uri() == null ? "" : request.uri();
    return DEFAULT_CREDENTIAL_CONTROL_PATH.matcher(uri).find();
  }

  private static RequestContext redactCredentialRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isCredentialPasswordName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    var headers = new LinkedHashMap<String, String>(request.headers());
    String authorization = headers.getOrDefault("authorization", "");
    if (authorization.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
      headers.put("authorization", "Basic [redacted]");
    }
    return new RequestContext(
        request.method(), request.uri(), redactCredentialQuery(request.query()), parameters, headers);
  }

  private static String redactCredentialQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      if (isCredentialPasswordName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean isCredentialPasswordName(String name) {
    return DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static Optional<EmptyCredentialBypassMatch> emptyCredentialBypass(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    String uri = request.uri() == null ? "" : request.uri();
    if (!EMPTY_CREDENTIAL_CONTROL_PATH.matcher(uri).find()) {
      return Optional.empty();
    }
    Optional<String> username =
        firstEmptyParameter(request.parameters(), EMPTY_CREDENTIAL_USERNAME_PARAMETERS);
    Optional<String> password =
        firstEmptyParameter(request.parameters(), EMPTY_CREDENTIAL_PASSWORD_PARAMETERS);
    Optional<String> bypass =
        firstPresentParameter(request.parameters(), EMPTY_CREDENTIAL_BYPASS_PARAMETERS);
    if (username.isPresent() && password.isPresent() && bypass.isPresent()) {
      return Optional.of(
          new EmptyCredentialBypassMatch(
              username.orElseThrow(), password.orElseThrow(), bypass.orElseThrow()));
    }
    return Optional.empty();
  }

  private static Optional<String> firstEmptyParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      String normalized = normalizeParameterName(entry.getKey());
      if (!candidateNames.contains(normalized)) {
        continue;
      }
      List<String> values = entry.getValue();
      if (values == null || values.isEmpty() || values.stream().allMatch(CredentialDetector::isBlank)) {
        return Optional.of(entry.getKey());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstPresentParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (String name : parameters.keySet()) {
      if (candidateNames.contains(normalizeParameterName(name))) {
        return Optional.of(name);
      }
    }
    return Optional.empty();
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private static Optional<String> jwtHmacAlgorithm(String headerPart) {
    String header;
    try {
      header = new String(Base64.getUrlDecoder().decode(headerPart), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    var matcher = JWT_HMAC_ALGORITHM.matcher(header);
    if (!matcher.find()) {
      return Optional.empty();
    }
    return Optional.of(matcher.group(1));
  }

  private static Optional<byte[]> jwtHmac(String signingInput, String jwtAlgorithm, String secret) {
    String macAlgorithm =
        switch (jwtAlgorithm) {
          case "HS256" -> "HmacSHA256";
          case "HS384" -> "HmacSHA384";
          case "HS512" -> "HmacSHA512";
          default -> "";
        };
    if (macAlgorithm.isBlank()) {
      return Optional.empty();
    }
    try {
      Mac mac = Mac.getInstance(macAlgorithm);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlgorithm));
      return Optional.of(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      return Optional.empty();
    }
  }
}
