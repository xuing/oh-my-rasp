package io.ohmyrasp.agent.rules.general;

import io.ohmyrasp.agent.util.WeakOwners;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Content evidence belongs to a successfully opened stream, across thread handoffs. */
public final class PlotWrite {
  private static final int WINDOW = 8192;
  private static final Pattern FILE = Pattern.compile("(?is).+\\.(?:gnuplot|gp|plt|plot)$");
  private static final Pattern DIRECTIVE = Pattern.compile(
      "(?:\\b(?:yrange|y2range|xrange|x2range|key)\\b[^\\r\\n]{0,300}\\b(?:system|shell)[ \\t]*\\(|\\bkey\\b[^\\r\\n]{0,300};[ \\t]*system[ \\t]+[a-zA-Z_(]|;[ \\t]*system[ \\t]*[\"'])");
  private static final WeakOwners<Stream> STREAMS = new WeakOwners<Stream>();

  private static final class Stream {
    final String path;
    String tail = "";
    PlotLine line;
    int active;
    boolean sharedPosition;
    long generation;
    Stream(String path, boolean append) { this.path = path; this.line = new PlotLine(append); }
  }

  private final Stream stream;
  private final long generation;
  private final boolean concurrent;
  private String tail;
  private final PlotLine line;
  private boolean directive;

  private PlotWrite(Stream stream) {
    this.stream = stream;
    synchronized (stream) {
      concurrent = stream.active++ != 0;
      if (concurrent) {
        stream.generation++;
        stream.tail = "";
        stream.line = new PlotLine(true);
      }
      generation = stream.generation;
      tail = stream.tail;
      line = new PlotLine(stream.line);
    }
  }

  public static void opened(Object owner, String path, boolean append) {
    if (path != null && FILE.matcher(path).matches()) STREAMS.put(owner, new Stream(path, append));
  }

  public static void closed(Object owner) { STREAMS.remove(owner); }

  public static void exposed(Object owner) {
    Stream s = STREAMS.get(owner);
    if (s != null) synchronized (s) {
      s.sharedPosition = true;
      s.generation++;
      s.tail = "";
      s.line = new PlotLine(true);
    }
  }

  public static PlotWrite bytes(Object owner, byte[] buffer, int offset, int length) {
    Stream stream = STREAMS.get(owner);
    if (stream == null || buffer == null || length <= 0 || offset < 0 || offset > buffer.length - length) return null;
    return prepare(stream, buffer, offset, length);
  }

  public static PlotWrite single(Object owner, int value) {
    Stream stream = STREAMS.get(owner);
    return stream == null ? null : prepare(stream, new byte[]{(byte)value}, 0, 1);
  }

  private static PlotWrite prepare(Stream stream, byte[] buffer, int offset, int length) {
    PlotWrite write = new PlotWrite(stream);
    try {
      int end = offset + length;
      while (offset < end) {
        int count = Math.min(WINDOW, end - offset);
        int previous = write.tail.length();
        String text = write.tail + write.line.code(buffer, offset, count);
        if (!write.directive) {
          Matcher matcher = DIRECTIVE.matcher(text);
          while (matcher.find()) {
            if (matcher.end() > previous) { write.directive = true; break; }
          }
        }
        int lastBreak = Math.max(text.lastIndexOf('\r'), text.lastIndexOf('\n'));
        write.tail = text.substring(Math.max(lastBreak + 1, text.length() - WINDOW));
        offset += count;
      }
      return write;
    } catch (RuntimeException | Error failure) {
      cancelled(write);
      throw failure;
    }
  }

  public String path() { return stream.path; }
  public boolean hasDirective() { return directive; }

  /** The guard stopped the call before the JDK wrote anything. */
  public static void cancelled(PlotWrite write) {
    if (write != null) synchronized (write.stream) { write.stream.active--; }
  }

  public static void finished(PlotWrite write, boolean success) {
    if (write == null) return;
    synchronized (write.stream) {
      Stream s = write.stream;
      s.active--;
      if (!success) {
        // An IOException can follow a partial write.
        s.generation++;
        s.tail = "";
        s.line = new PlotLine(true);
      } else if (!s.sharedPosition && s.active == 0 && !write.concurrent && s.generation == write.generation) {
        s.tail = write.tail;
        s.line = write.line;
      }
    }
  }
}
