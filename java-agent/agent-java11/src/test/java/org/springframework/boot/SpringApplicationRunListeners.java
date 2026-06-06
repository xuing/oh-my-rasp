package org.springframework.boot;

public final class SpringApplicationRunListeners {
  private SpringApplicationRunListeners() {}

  public interface CheckedRunnable {
    void run() throws Exception;
  }

  public static void ready(CheckedRunnable action) throws Exception {
    action.run();
  }
}
