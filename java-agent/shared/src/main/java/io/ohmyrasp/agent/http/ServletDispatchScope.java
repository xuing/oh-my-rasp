package io.ohmyrasp.agent.http;

/** Suspends request-bound hook state while another servlet dispatch runs on the same thread. */
public final class ServletDispatchScope<R, C> {
  private final ThreadLocal<R> request;
  private final ThreadLocal<C> companion;
  private final ThreadLocal<?> archiveEntry;
  private final ThreadLocal<Saved<R, C>> active = new ThreadLocal<Saved<R, C>>();

  public ServletDispatchScope(ThreadLocal<R> request, ThreadLocal<C> companion, ThreadLocal<?> archiveEntry) {
    this.request = request;
    this.companion = companion;
    this.archiveEntry = archiveEntry;
  }

  public void enteredApplication() {
    active.get().inspecting = false;
  }

  public boolean inspectingRequest() {
    Saved<R, C> frame = active.get();
    return frame != null && frame.inspecting;
  }

  public Object servletRequest() {
    Saved<R, C> scope = active.get();
    return scope == null ? null : scope.servletRequest;
  }

  /** Track a lookup result without asking the request or a collection for its contents again. */
  public void multipartResult(Object lookup, Object result, int kind, boolean bulk) {
    Saved<R, C> frame = active.get();
    if (frame == null || frame.inspecting || result == null || !MultipartFilename.source(frame.servletRequest, lookup, kind)) return;
    int partKind = kind == MultipartFilename.SERVLET_REQUEST ? MultipartFilename.PART : MultipartFilename.SPRING;
    if (bulk && result instanceof java.util.Collection<?>) frame.remember(result, partKind << 2);
    else if (!bulk) frame.remember(result, MultipartFilename.partKinds(result) & partKind);
  }

  public void multipartAccess(Object source, Object result, boolean iterator) {
    Saved<R, C> frame = active.get();
    if (frame == null || frame.inspecting || frame.parts == null || result == null) return;
    int partKinds = frame.flags(source) >>> 2;
    if (partKinds == 0) return;
    if (iterator && result instanceof java.util.Iterator<?>) frame.remember(result, partKinds << 2);
    else if (!iterator) frame.remember(result, MultipartFilename.partKinds(result) & partKinds);
  }

  public boolean deliveredPart(Object part) {
    Saved<R, C> frame = active.get();
    int contract = MultipartFilename.kind() & (MultipartFilename.PART | MultipartFilename.SPRING);
    return contract != 0 && frame != null && frame.parts != null && (frame.flags(part) & contract) != 0;
  }

  /** A repeated entry on the same request can observe the same policy decision in both service overloads. */
  public boolean repeatedAdmission(Object observation) {
    Saved<R, C> frame = active.get();
    if (frame == null || !frame.inspecting || frame.servletRequest == null) return false;
    if (frame.genericService) {
      if (frame.observations == null) frame.observations = new java.util.ArrayList<Object>();
      frame.observations.add(observation);
    } else {
      Saved<R, C> parent = frame.parent;
      return parent != null && parent.servletRequest == frame.servletRequest && parent.observations != null
          && parent.observations.remove(observation);
    }
    return false;
  }

  public void enter(Object servletRequest) {
    enter(servletRequest, false);
  }

  public void enter(Object servletRequest, boolean genericService) {
    Saved<R, C> parent = active.get();
    active.set(parent == null ? new Saved<R, C>(servletRequest, null, null, null, null)
        : new Saved<R, C>(servletRequest, parent, request.get(), companion.get(), restoreLater(archiveEntry)));
    active.get().genericService = genericService;
    request.remove();
    companion.remove();
    archiveEntry.remove();
  }

  public void exit() {
    Saved<R, C> saved = active.get();
    if (saved == null || saved.parent == null) {
      active.remove();
      request.remove();
      companion.remove();
      archiveEntry.remove();
      return;
    }
    active.set(saved.parent);
    request.set(saved.request);
    companion.set(saved.companion);
    saved.restoreArchive.run();
  }

  // Anonymous classes, not lambdas: backport hooks run this, and a lambda links at run time.
  private static <T> Runnable restoreLater(final ThreadLocal<T> slot) {
    final T previous = slot.get();
    if (previous == null) {
      return new Runnable() {
        public void run() {
          slot.remove();
        }
      };
    }
    return new Runnable() {
      public void run() {
        slot.set(previous);
      }
    };
  }

  private static final class Saved<R, C> {
    // The low bits identify directly delivered parts; the next two carry the element
    // contracts of a returned collection or iterator. One object can serve both APIs.
    io.ohmyrasp.agent.util.WeakOwners<Integer> parts;
    int flags(Object value) {
      Integer bits = parts.get(value);
      return bits == null ? 0 : bits;
    }
    void remember(Object value, int bits) {
      if (bits == 0) return;
      if (parts == null) parts = new io.ohmyrasp.agent.util.WeakOwners<Integer>();
      parts.put(value, flags(value) | bits);
    }
    java.util.List<Object> observations;
    boolean genericService;
    boolean inspecting = true;
    final Object servletRequest;
    final Saved<R, C> parent;
    final R request;
    final C companion;
    final Runnable restoreArchive;

    Saved(Object servletRequest, Saved<R, C> parent, R request, C companion, Runnable restoreArchive) {
      this.servletRequest = servletRequest;
      this.parent = parent;
      this.request = request;
      this.companion = companion;
      this.restoreArchive = restoreArchive;
    }
  }
}
