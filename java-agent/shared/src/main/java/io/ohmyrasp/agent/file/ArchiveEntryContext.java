package io.ohmyrasp.agent.file;

import java.io.IOException;
import java.nio.file.Path;

/** The pending archive member is scoped to a dispatch and consumed by a write attempt. */
public final class ArchiveEntryContext extends ThreadLocal<String> {
  public void observe(String name) {
    if (EscapingPath.mayEscape(name)) set(name);
    else remove();
  }

  public String take() {
    String name = get();
    if (name != null) remove();
    return name;
  }

  public boolean hostDestination(Object operand) {
    if (HostFileSystem.contains(operand)) return true;
    remove();
    return false;
  }

  public ChannelWrite atChannelOpen(Path path, int directoryFd) {
    String name = take();
    if (name == null) return null;
    try {
      Path target = HostFileSystem.absoluteOperand(path, directoryFd);
      if (target == null) return null;
      return new ChannelWrite(name, target.toString(),
          directoryFd >= 0 && !path.isAbsolute() ? "archive_descriptor_open" : "archive_channel_open");
    } catch (IOException | SecurityException unavailable) {
      return null;
    }
  }

  public static final class ChannelWrite {
    public final String member;
    public final String target;
    public final String basis;

    private ChannelWrite(String member, String target, String basis) {
      this.member = member;
      this.target = target;
      this.basis = basis;
    }
  }
}
