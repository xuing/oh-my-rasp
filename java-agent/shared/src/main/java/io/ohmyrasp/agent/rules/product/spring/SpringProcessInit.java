package io.ohmyrasp.agent.rules.product.spring;

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
    if (connection instanceof HttpURLConnection && connection.getClass().getClassLoader() == null && stream != null)
      STREAMS.put(stream, new WeakReference<Object>(resource));
  }

  public static void enterParse(InputSource input, Object resource) {
    WeakReference<Object> opened = input != null && input.getClass() == InputSource.class && input.getCharacterStream() == null
        ? STREAMS.remove(input.getByteStream()) : null;
    Parse parent = PARSING.get();
    boolean matched = resource != null && opened != null && opened.get() == resource;
    if (matched || parent != null) PARSING.set(new Parse(parent, matched ? resource : null));
  }

  public static void exitParse() {
    Parse parse = PARSING.get();
    if (parse == null || parse.parent == null) PARSING.remove();
    else PARSING.set(parse.parent);
  }

  public static void replaced(Object definition) {
    DEFINITIONS.remove(definition);
    Parse parse = PARSING.get();
    if (parse != null && parse.initializers != null) parse.initializers.remove(definition);
  }

  public static void declared(Object definition, String method) {
    Parse parse = PARSING.get();
    if (parse == null || parse.resource == null
        || !("start".equals(method) || "java.lang.ProcessBuilder.start".equals(method))) return;
    if (parse.initializers == null) parse.initializers = new IdentityHashMap<Object, Boolean>();
    parse.initializers.put(definition, Boolean.TRUE);
  }

  public static void assigned(Object definition, Object resource) {
    Parse scope = PARSING.get();
    if (resource != null && scope != null && scope.resource == resource && scope.initializers != null
        && scope.initializers.containsKey(definition)) DEFINITIONS.put(definition, Boolean.TRUE);
  }

  public static void copied(Object target, Object source) {
    // Without an overriding init method Spring retains the inherited setting.
    // An explicit local setter already cleared the old binding.
    if (source != null && DEFINITIONS.get(source) != null) DEFINITIONS.put(target, Boolean.TRUE);
  }

  public static void enterInit(Object bean, Object definition) {
    boolean selected = bean instanceof ProcessBuilder && definition != null && DEFINITIONS.get(definition) != null;
    Init parent = INITIALIZING.get();
    if (selected || parent != null) INITIALIZING.set(new Init(parent, selected ? (ProcessBuilder) bean : null));
  }

  public static void dispatch(Method method, Object receiver) {
    Init scope = INITIALIZING.get();
    if (scope != null && scope.builder == receiver && receiver instanceof ProcessBuilder)
      scope.dispatched = method.getDeclaringClass() == ProcessBuilder.class && "start".equals(method.getName())
          && method.getParameterCount() == 0;
  }

  public static boolean selects(ProcessBuilder builder) {
    Init scope = INITIALIZING.get();
    return builder != null && scope != null && scope.builder == builder && scope.dispatched;
  }

  public static void exitInit() {
    Init scope = INITIALIZING.get();
    if (scope == null || scope.parent == null) INITIALIZING.remove();
    else INITIALIZING.set(scope.parent);
  }
}
