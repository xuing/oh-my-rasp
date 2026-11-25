package io.ohmyrasp.agent.hook;

/** Evidence local to one Files.write(Iterable) call; application iterators are never stored. */
public final class GeneratedLineWrite {
  private static final int LIMIT = 8192;
  final String path;
  private final StringBuilder prefix = new StringBuilder();
  private boolean complete;
  private boolean reported;

  GeneratedLineWrite(String path) { this.path = path; }

  String append(String line) {
    if (line == null || complete) return null;
    if (line.length() >= LIMIT - prefix.length()) {
      // Inspect the whole line that crosses the collection budget, just as the original
      // iterable probe did, without retaining an oversized buffer or requesting more elements.
      complete = true;
      return prefix.length() == 0 ? line : prefix.toString() + line;
    }
    prefix.append(line).append('\n');
    return prefix.toString();
  }

  boolean repeated() {
    boolean prior = reported;
    reported = true;
    return prior;
  }
}
