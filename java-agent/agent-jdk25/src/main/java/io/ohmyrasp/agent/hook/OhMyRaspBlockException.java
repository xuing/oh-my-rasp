package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.model.Detection;

public final class OhMyRaspBlockException extends RuntimeException {
  private final Detection detection;

  public OhMyRaspBlockException(Detection detection) {
    super(detection == null ? "OhMyRasp blocked request" : detection.message());
    this.detection = detection;
  }

  public Detection detection() {
    return detection;
  }
}
