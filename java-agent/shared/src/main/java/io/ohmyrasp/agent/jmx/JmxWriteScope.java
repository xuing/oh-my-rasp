package io.ohmyrasp.agent.jmx;

import io.ohmyrasp.agent.hook.HookActivation;
import java.util.Collections;
import java.util.List;

/** Text supplied to the innermost synchronous management invocation. */
public final class JmxWriteScope {
  private static final ThreadLocal<JmxWriteScope> CURRENT = new ThreadLocal<JmxWriteScope>();
  private final JmxWriteScope parent;
  private List<String> arguments = Collections.emptyList();
  private String bean;
  private String operation;

  private JmxWriteScope(JmxWriteScope parent) { this.parent = parent; }

  /** Opens the scope of one invocation; returns it as the token {@link #exit} takes, or null while the hooks are off. */
  public static Object enter() {
    if (HookActivation.inactive()) return null;
    JmxWriteScope scope = new JmxWriteScope(CURRENT.get());
    CURRENT.set(scope);
    return scope;
  }

  public static void clearArguments() {
    if (HookActivation.inactive()) return;
    JmxWriteScope scope = CURRENT.get();
    if (scope != null) scope.arguments = Collections.emptyList();
  }

  /** Closes the scope {@code token} opened: the thread's scope is its parent again. Null opened none. */
  public static void exit(Object token) {
    if (token == null) return;
    JmxWriteScope parent = ((JmxWriteScope) token).parent;
    if (parent == null) CURRENT.remove();
    else CURRENT.set(parent);
  }

  public static void select(String bean, String operation, List<String> arguments) {
    JmxWriteScope scope = CURRENT.get();
    if (scope != null) {
      scope.bean = bean;
      scope.operation = operation == null ? "" : operation;
      scope.arguments = arguments;
    }
  }

  public static JmxWriteScope current() { return CURRENT.get(); }
  public String bean() { return bean; }
  public String operation() { return operation; }

  public boolean selects(String path) {
    if (path == null || path.isEmpty()) return false;
    for (String value : arguments) {
      if (path.equals(value)) return true;
      if (value == null || value.indexOf(path) < 0) continue;
      // Configuration text can supply a quoted, complete destination value.
      if (value.contains("\"" + path + "\"") || value.contains("'" + path + "'")) return true;
    }
    return false;
  }
}
