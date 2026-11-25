package io.ohmyrasp.agent.xml;

import io.ohmyrasp.agent.util.WeakOwners;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Carries a package reader's local reference to the actual read by its activation data source. */
public final class AttachmentFileRead {
  private static final WeakOwners<Reference> SOURCES = new WeakOwners<Reference>();
  private static final ThreadLocal<Scope> REFERENCES = new ThreadLocal<Scope>();
  private static final ThreadLocal<Scope> READS = new ThreadLocal<Scope>();

  private AttachmentFileRead() {}

  private static final class Reference {
    final Path path;
    final Object origin;
    Reference(Path path, Object origin) { this.path = path; this.origin = origin; }
  }

  private static final class Scope {
    final Reference reference;
    final Scope parent;
    boolean reported;
    Scope(Reference reference, Scope parent) { this.reference = reference; this.parent = parent; }
  }

  private static void push(ThreadLocal<Scope> stack, Reference reference) {
    Scope parent = stack.get();
    if (reference != null || parent != null) stack.set(new Scope(reference, parent));
  }

  private static void pop(ThreadLocal<Scope> stack) {
    Scope top = stack.get();
    if (top == null) return;
    if (top.parent == null) stack.remove();
    else stack.set(top.parent);
  }

  private static Path localPath(String reference) {
    if (reference == null || !reference.regionMatches(true, 0, "file:", 0, 5)) return null;
    try {
      URI uri = new URI(reference);
      if (uri.getRawAuthority() != null || uri.isOpaque() || uri.getPath() == null) return null;
      Path path = Paths.get(new URI("file", null, uri.getPath(), null));
      return path.isAbsolute() ? path : null;
    } catch (URISyntaxException | IllegalArgumentException invalid) {
      return null;
    }
  }

  public static void beginReference(String id, Object origin) {
    Path path = localPath(id);
    push(REFERENCES, path == null ? null : new Reference(path, origin));
  }
  public static void endReference() { pop(REFERENCES); }

  public static void created(Object source, URL url) {
    Scope ref = REFERENCES.get();
    if (ref == null || ref.reference == null || url == null || !"file".equalsIgnoreCase(url.getProtocol())
        || (url.getAuthority() != null && !url.getAuthority().isEmpty())) return;
    if (ref.reference.path.equals(localPath("file:" + url.getPath()))) SOURCES.put(source, ref.reference);
  }

  public static void beginRead(Object source) { push(READS, SOURCES.get(source)); }
  public static void endRead() { pop(READS); }

  /** More than one JDK entry point can observe a single source materialization. */
  public static boolean repeated() {
    Scope read = READS.get();
    if (read == null) return false;
    boolean prior = read.reported;
    read.reported = true;
    return prior;
  }

  public static Object origin() {
    Scope read = READS.get();
    return read == null || read.reference == null ? null : read.reference.origin;
  }

  public static boolean selected(String path) {
    Scope read = READS.get();
    if (read == null || read.reference == null || path == null) return false;
    try {
      return read.reference.path.equals(Paths.get(path));
    } catch (InvalidPathException invalid) {
      return false;
    }
  }
}
