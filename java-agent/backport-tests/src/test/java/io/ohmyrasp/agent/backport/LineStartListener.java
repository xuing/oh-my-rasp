package io.ohmyrasp.agent.backport;

import io.ohmyrasp.agent.java8.Java8RaspLine;
import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

/**
 * Starts the line under test before any test class loads, as the line's entry class starts it before any hook is
 * installed. The runtime refuses to run until a line has started, so a test never runs it for a default line.
 * Registered in META-INF/services; a test that needs a runtime that has not started uses its own class loader.
 */
public final class LineStartListener implements LauncherSessionListener {
  @Override
  public void launcherSessionOpened(LauncherSession session) {
    Java8RaspLine.start();
  }
}
