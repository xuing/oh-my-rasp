package io.ohmyrasp.agent.rules.product.spark;

import io.ohmyrasp.agent.http.ServletSubmitRole;

/** Check the deployment's required role on a validated Spark creation request. */
public final class SparkSubmitRole {
  private SparkSubmitRole() {}

  public static boolean denied(boolean creation, Object request, Class<?> requestApi) {
    return creation && ServletSubmitRole.denied("ohmyrasp.spark.submitRole", request, requestApi);
  }
}
