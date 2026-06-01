package io.ohmyrasp.agent.policy;

import io.ohmyrasp.agent.model.Detection;

public record PolicyEvaluation(boolean controlled, boolean ignored, Detection detection) {
  public static PolicyEvaluation notControlled(Detection detection) {
    return new PolicyEvaluation(false, false, detection);
  }

  public static PolicyEvaluation ignore() {
    return new PolicyEvaluation(true, true, null);
  }

  public static PolicyEvaluation emit(Detection detection) {
    return new PolicyEvaluation(true, false, detection);
  }
}
