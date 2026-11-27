package io.ohmyrasp.agent.rules.product.spring;

import io.ohmyrasp.agent.hook.HookActivation;
import io.ohmyrasp.agent.util.WeakOwners;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.util.IdentityHashMap;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.lang.reflect.Method;
import org.xml.sax.InputSource;

/** Carry the parser's resource identity through definition creation, merging and custom initialization. */
public final class SpringProcessInit {
  private static final WeakOwners<WeakReference<Object>> STREAMS = new WeakOwners<WeakReference<Object>>();
  private static final WeakOwners<Boolean> DEFINITIONS = new WeakOwners<Boolean>();
  private static final ThreadLocal<Parse> PARSING = new ThreadLocal<Parse>();
  private static final ThreadLocal<Init> INITIALIZING = new ThreadLocal<Init>();

  private SpringProcessInit() {}

  private static final class Parse {
    final Parse parent;
    final Object resource;
    IdentityHashMap<Object, Boolean> initializers;
    Parse(Parse parent, Object resource) { this.parent = parent; this.resource = resource; }
  }

  private static final class Init {
    final Init parent;
    final ProcessBuilder builder;
    boolean dispatched;
    Init(Init parent, ProcessBuilder builder) { this.parent = parent; this.builder = builder; }
  }

  public static void opened(URLConnection connection, InputStream stream, Object resource) {
    if (HookActivation.inactive()) return;
    if (connection instanceof HttpURLConnection && connection.getClass().getClassLoader() == null && stream != null)
      STREAMS.put(stream, new WeakReference<Object>(resource));
  }

  /** Enters one parse; returns the scope it opened, as the token {@link #exitParse} takes, or null when none. */
  public static Object enterParse(InputSource input, Object resource) {
    if (HookActivation.inactive()) return null;
    WeakReference<Object> opened = input != null && input.getClass() == InputSource.class && input.getCharacterStream() == null
        ? STREAMS.remove(input.getByteStream()) : null;
    Parse parent = PARSING.get();
    boolean matched = resource != null && opened != null && opened.get() == resource;
    if (!matched && parent == null) return null;
    Parse parse = new Parse(parent, matched ? resource : null);
    PARSING.set(parse);
    return parse;
  }

  /** Leaves the parse {@code token} entered: the thread's parse is its parent again. Null entered none. */
  public static void exitParse(Object token) {
    if (token == null) return;
    Parse parent = ((Parse) token).parent;
    if (parent == null) PARSING.remove();
    else PARSING.set(parent);
  }

  public static void replaced(Object definition) {
    if (HookActivation.inactive()) return;
    DEFINITIONS.remove(definition);
    Parse parse = PARSING.get();
    if (parse != null && parse.initializers != null) parse.initializers.remove(definition);
  }

  public static void declared(Object definition, String method) {
    if (HookActivation.inactive()) return;
    Parse parse = PARSING.get();
    if (parse == null || parse.resource == null
        || !("start".equals(method) || "java.lang.ProcessBuilder.start".equals(method))) return;
    if (parse.initializers == null) parse.initializers = new IdentityHashMap<Object, Boolean>();
    parse.initializers.put(definition, Boolean.TRUE);
  }

  public static void assigned(Object definition, Object resource) {
    if (HookActivation.inactive()) return;
    Parse scope = PARSING.get();
    if (resource != null && scope != null && scope.resource == resource && scope.initializers != null
        && scope.initializers.containsKey(definition)) DEFINITIONS.put(definition, Boolean.TRUE);
  }

  public static void copied(Object target, Object source) {
    if (HookActivation.inactive()) return;
    // Without an overriding init method Spring retains the inherited setting.
    // An explicit local setter already cleared the old binding.
    if (source != null && DEFINITIONS.get(source) != null) DEFINITIONS.put(target, Boolean.TRUE);
  }

  /** Enters one custom init; returns the scope it opened, as the token {@link #exitInit} takes, or null when none. */
  public static Object enterInit(Object bean, Object definition) {
    if (HookActivation.inactive()) return null;
    boolean selected = bean instanceof ProcessBuilder && definition != null && DEFINITIONS.get(definition) != null;
    Init parent = INITIALIZING.get();
    if (!selected && parent == null) return null;
    Init init = new Init(parent, selected ? (ProcessBuilder) bean : null);
    INITIALIZING.set(init);
    return init;
  }

  public static void dispatch(Method method, Object receiver) {
    if (HookActivation.inactive()) return;
    Init scope = INITIALIZING.get();
    if (scope != null && scope.builder == receiver && receiver instanceof ProcessBuilder)
      scope.dispatched = method.getDeclaringClass() == ProcessBuilder.class && "start".equals(method.getName())
          && method.getParameterCount() == 0;
  }

  public static boolean selects(ProcessBuilder builder) {
    Init scope = INITIALIZING.get();
    return builder != null && scope != null && scope.builder == builder && scope.dispatched;
  }

  /** Leaves the init {@code token} entered: the thread's init is its parent again. Null entered none. */
  public static void exitInit(Object token) {
    if (token == null) return;
    Init parent = ((Init) token).parent;
    if (parent == null) INITIALIZING.remove();
    else INITIALIZING.set(parent);
  }
}
