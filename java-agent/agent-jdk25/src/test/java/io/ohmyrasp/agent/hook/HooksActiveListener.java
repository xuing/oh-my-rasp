package io.ohmyrasp.agent.hook;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

/**
 * Turns the hooks on before any test runs, as a start that committed does: the tests call hook entries directly,
 * and an entry does nothing while the hooks are off. Registered in META-INF/services. A test of the inactive hooks
 * turns them off itself and on again when it ends ({@link HookActivationTest}); a JVM a test starts (the
 * start-failure tests) has no listener and starts with the hooks off.
 */
public final class HooksActiveListener implements LauncherSessionListener {
  @Override
  public void launcherSessionOpened(LauncherSession session) {
    HookActivation.activate();
  }
}
