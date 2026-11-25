package io.ohmyrasp.agent.http;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

/** A deployment's explicit policy for Java archive uploads to one servlet operation. */
public final class ArchiveUploadPolicy {
  private static final ThreadLocal<Boolean> CHECKING = new ThreadLocal<Boolean>();
  private static final Pattern ARCHIVE = Pattern.compile("(?is).+\\.(?:jar|war|ear|class)\\.?$");

  public enum Decision {
    UNSPECIFIED, ALLOWED, ROLE_DENIED, DENY_ALL, UNAVAILABLE;

    public String denialBasis() {
      if (this == ROLE_DENIED) return "required_role_denied";
      if (this == DENY_ALL) return "archive_upload_denied";
      return null;
    }
  }

  /** The digest binds a denial to a declared key/value, without retaining the request or principal. */
  public static final class Evaluation {
    public final Decision decision;
    public final String policyDigest;
    private Evaluation(Decision decision, String digest) { this.decision = decision; this.policyDigest = digest; }
  }
  public static final Evaluation UNSPECIFIED = new Evaluation(Decision.UNSPECIFIED, null);
  private static final Evaluation ALLOWED = new Evaluation(Decision.ALLOWED, null);
  private static final Evaluation UNAVAILABLE = new Evaluation(Decision.UNAVAILABLE, null);
  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private static Evaluation denied(Decision decision, String key, String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(key.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      char[] hex = new char[2 * bytes.length];
      for (int i = 0; i < bytes.length; i++) {
        hex[2 * i] = HEX[(bytes[i] & 255) >>> 4];
        hex[2 * i + 1] = HEX[bytes[i] & 15];
      }
      return new Evaluation(decision, new String(hex));
    } catch (NoSuchAlgorithmException | RuntimeException unavailable) {
      return new Evaluation(decision, null);
    }
  }

  private ArchiveUploadPolicy() {}

  public static boolean isArchive(String filename) {
    return filename != null && ARCHIVE.matcher(filename).matches();
  }

  public static Decision decide(Object request) { return inspect(request).decision; }

  public static Evaluation inspect(Object request) {
    if (request == null) return UNSPECIFIED;
    if (Boolean.TRUE.equals(CHECKING.get())) return UNAVAILABLE;
    CHECKING.set(Boolean.TRUE);
    try {
      Object contentType = call(request, "getContentType");
      if (!(contentType instanceof String)
          || !((String) contentType).trim().regionMatches(true, 0, "multipart/", 0, 10)) {
        return UNAVAILABLE;
      }
      Object context = call(request, "getServletContext");
      if (context == null) return UNSPECIFIED;
      // An include exposes the caller's servlet path.
      Object dispatcher = call(request, "getDispatcherType");
      if (dispatcher == null || "INCLUDE".equals(dispatcher.toString())) return UNAVAILABLE;
      Object verb = call(request, "getMethod");
      Object servletPath = call(request, "getServletPath");
      Object info = call(request, "getPathInfo");
      if (!(verb instanceof String) || !(servletPath instanceof String)) return UNAVAILABLE;
      String path = (String) servletPath + (info == null ? "" : (String) info);
      if (!path.startsWith("/")) return UNAVAILABLE;
      String key = "ohmyrasp.archiveUpload." + verb + path;
      Object policy = call(context, "getInitParameter", key);
      if (policy == null) return UNSPECIFIED;
      String value = ((String) policy).trim();
      if ("deny".equals(value)) return denied(Decision.DENY_ALL, key, value);
      if (!value.startsWith("role:")) return UNAVAILABLE;
      String role = value.substring(5).trim();
      if (role.isEmpty() || "*".equals(role) || "**".equals(role)) return UNAVAILABLE;
      Object authorized = call(request, "isUserInRole", role);
      if (Boolean.TRUE.equals(authorized)) return ALLOWED;
      return Boolean.FALSE.equals(authorized) ? denied(Decision.ROLE_DENIED, key, value) : UNAVAILABLE;
    } catch (ReflectiveOperationException | RuntimeException unavailable) {
      return UNAVAILABLE;
    } finally {
      CHECKING.remove();
    }
  }

  private static Object call(Object receiver, String name, String... argument) throws ReflectiveOperationException {
    Class<?>[] types = argument.length == 0 ? new Class<?>[0] : new Class<?>[]{String.class};
    Method method = receiver.getClass().getMethod(name, types);
    if (!Modifier.isPublic(method.getDeclaringClass().getModifiers())) {
      // Application request wrappers can be private classes implementing a public servlet API.
      for (String namespace : new String[]{"javax.servlet", "jakarta.servlet"}) {
        String api = name.equals("getInitParameter") ? ".ServletContext" : ".http.HttpServletRequest";
        try {
          Class<?> contract = Class.forName(namespace + api, false, receiver.getClass().getClassLoader());
          if (contract.isInstance(receiver)) {
            method = contract.getMethod(name, types);
            break;
          }
        } catch (ClassNotFoundException unusedNamespace) {
          // Only the active servlet namespace is required.
        }
      }
    }
    return method.invoke(receiver, (Object[]) argument);
  }
}
