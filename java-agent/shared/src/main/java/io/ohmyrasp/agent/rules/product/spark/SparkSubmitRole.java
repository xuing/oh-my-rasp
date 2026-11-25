package io.ohmyrasp.agent.rules.product.spark;

/** Check the deployment's required role on the actual submitting servlet request. */
public final class SparkSubmitRole {
  private SparkSubmitRole() {}

  public static boolean denied(boolean creation, Object request, Class<?> requestApi) {
    if (!creation || request == null) return false;
    try {
      String role = System.getProperty("ohmyrasp.spark.submitRole", "").trim();
      if (role.isEmpty() || "*".equals(role) || "**".equals(role)) return false;
      return Boolean.FALSE.equals(requestApi.getMethod("isUserInRole", String.class).invoke(request, role));
    } catch (ReflectiveOperationException | RuntimeException | LinkageError unavailable) {
      return false;
    }
  }
}
