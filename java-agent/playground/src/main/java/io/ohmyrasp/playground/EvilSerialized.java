package io.ohmyrasp.playground;

import java.io.Serializable;

public final class EvilSerialized implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String marker;

  public EvilSerialized(String marker) {
    this.marker = marker;
  }

  public String marker() {
    return marker;
  }
}
