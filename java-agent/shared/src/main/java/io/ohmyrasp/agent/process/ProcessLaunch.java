package io.ohmyrasp.agent.process;

/** Preserve which public Runtime overload led to a launch without reading a mutable builder or retaining argv. */
public final class ProcessLaunch {
  private static final ThreadLocal<Entry> ENTRIES = new ThreadLocal<Entry>();
  private ProcessLaunch() {}

  private static final class Entry {
    final Entry parent;
    final boolean stringMethod;
    final boolean fromString;
    Entry(Entry parent, boolean stringMethod) {
      this.parent = parent;
      this.stringMethod = stringMethod;
      this.fromString = stringMethod || (parent != null && parent.stringMethod);
    }
  }

  public static void enter(boolean stringMethod) {
    ENTRIES.set(new Entry(ENTRIES.get(), stringMethod));
  }

  public static void exit() {
    Entry current = ENTRIES.get();
    if (current == null || current.parent == null) ENTRIES.remove();
    else ENTRIES.set(current.parent);
  }

  public static String api() {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (int i = 0; i + 1 < stack.length; i++) {
      if (!"java.lang.ProcessImpl".equals(stack[i].getClassName()) || !"start".equals(stack[i].getMethodName())) continue;
      int caller = i + 1;
      while (caller < stack.length && "java.lang.ProcessBuilder".equals(stack[caller].getClassName())) {
        if ("startPipeline".equals(stack[caller].getMethodName())) return "ProcessBuilder.startPipeline";
        caller++;
      }
      if (caller < stack.length && "java.lang.Runtime".equals(stack[caller].getClassName())
          && "exec".equals(stack[caller].getMethodName())) {
        Entry entry = ENTRIES.get();
        return entry != null && entry.fromString ? "Runtime.exec(String)" : "Runtime.exec(String[])";
      }
      return caller > i + 1 ? "ProcessBuilder.start" : "ProcessImpl.start";
    }
    return null;
  }
}
