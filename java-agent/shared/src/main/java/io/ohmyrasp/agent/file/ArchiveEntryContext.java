package io.ohmyrasp.agent.file;

import io.ohmyrasp.agent.util.WeakOwners;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.file.Path;

/** The pending archive member is scoped to a dispatch and consumed by a write attempt. */
public final class ArchiveEntryContext extends ThreadLocal<ArchiveEntryContext.Member> {
  private static final class Reader extends WeakReference<Object> {
    volatile boolean closed;
    Reader(Object reader) { super(reader); }
  }

  private final WeakOwners<Reader> readers = new WeakOwners<Reader>();

  static final class Member {
    final String name;
    final Reader owner;
    Member(String name, Reader owner) { this.name = name; this.owner = owner; }
  }

  public void observe(String name) { observe(null, name); }

  public void observe(Object owner, String name) {
    if (!EscapingPath.mayEscape(name)) { remove(); return; }
    Reader reader = null;
    if (owner != null) {
      reader = readers.get(owner);
      if (reader == null) reader = readers.putIfAbsent(owner, new Reader(owner));
    }
    set(new Member(name, reader));
  }

  public void closed(Object owner) {
    Reader reader = readers.remove(owner);
    if (reader == null) return;
    // A suspended outer dispatch can still hold this reader's observation.
    reader.closed = true;
    Member member = get();
    if (member != null && member.owner == reader) remove();
  }

  public String take() {
    Member member = get();
    if (member == null) return null;
    remove();
    return member.owner == null || (!member.owner.closed && member.owner.get() != null) ? member.name : null;
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
