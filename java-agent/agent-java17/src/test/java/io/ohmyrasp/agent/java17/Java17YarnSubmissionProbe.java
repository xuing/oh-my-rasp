package io.ohmyrasp.agent.java17;

import java.util.List;

public final class Java17YarnSubmissionProbe {
  private final Container container;

  public Java17YarnSubmissionProbe(List<String> commands) {
    this.container = new Container(commands);
  }

  public Object getContainerLaunchContextInfo() {
    return container;
  }

  public String getApplicationType() {
    return "YARN";
  }

  public static final class Container {
    private final List<String> commands;

    Container(List<String> commands) {
      this.commands = commands;
    }

    public List<String> getCommands() {
      return commands;
    }
  }
}
