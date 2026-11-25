package io.ohmyrasp.agent.hook;

import io.ohmyrasp.agent.model.Detection;

public final class OhMyRaspBlockException extends RuntimeException {
  private final Detection detection;

  private final boolean redirected;

  public OhMyRaspBlockException(Detection detection) {
    this(detection, false);
  }

  OhMyRaspBlockException(Detection detection, boolean redirected) {
    super(detection == null ? "OhMyRasp blocked request" : detection.message());
    this.detection = detection;
    this.redirected = redirected;
  }

  boolean redirected() { return redirected; }

  public Detection detection() {
    return detection;
  }
}
