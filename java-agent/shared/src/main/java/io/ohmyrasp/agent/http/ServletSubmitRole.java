package io.ohmyrasp.agent.http;

/** Check the deployment's required role on the actual submitting servlet request. */
public final class ServletSubmitRole {
  private ServletSubmitRole() {}

  public static boolean denied(String property, Object request, Class<?> requestApi) {
    if (request == null) return false;
    try {
      String role = System.getProperty(property, "").trim();
      if (role.isEmpty() || "*".equals(role) || "**".equals(role)) return false;
      return Boolean.FALSE.equals(requestApi.getMethod("isUserInRole", String.class).invoke(request, role));
    } catch (ReflectiveOperationException | RuntimeException | LinkageError unavailable) {
      return false;
    }
  }
}
