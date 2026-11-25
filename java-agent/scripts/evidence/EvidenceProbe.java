import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/** Calls only detector entry points. Inputs are data, including class names and script text. */
public final class EvidenceProbe {
  public static final class RecordedRequest {
    private final String uri;

    private final String userAgent;

    RecordedRequest(String uri, String userAgent) { this.uri = uri; this.userAgent = userAgent; }

    public String getHeader(String name) { return "User-Agent".equalsIgnoreCase(name) ? userAgent : null; }

    public String getRequestURI() { return uri; }
  }

  public static void main(String[] args) throws Exception {
    String track = args[0];
    if (!track.matches("8|11|17")) throw new IllegalArgumentException("unknown agent track");
    String prefix = "io.ohmyrasp.agent.java" + track + ".Java" + track;
    Class<?> hooks = Class.forName(prefix + "RaspHooks");
    Path log = Paths.get(args[1]);
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    String line;
    while ((line = in.readLine()) != null) {
      String[] fields = line.split("\t", -1);
      String value = new String(Base64.getDecoder().decode(fields[1]), StandardCharsets.UTF_8);
      String methodName = fields[0];
      Class<?>[] parameters = {String.class};
      Object[] arguments = {value};
      switch (methodName) {
        case "requestPath":
          methodName = "beforeHttpRequest";
          parameters[0] = Object.class;
          arguments[0] = new RecordedRequest(value, null);
          break;
        case "requestIdentity":
          int delimiter = value.indexOf('\0');
          if (delimiter < 0) throw new IllegalArgumentException("missing identity argument boundary");
          methodName = "beforeHttpRequest";
          parameters[0] = Object.class;
          arguments[0] = new RecordedRequest(value.substring(delimiter + 1), value.substring(0, delimiter));
          break;
        case "archiveWrite":
          String[] paths = value.split(" -> ", -1);
          if (paths.length != 2) throw new IllegalArgumentException("ambiguous archive paths");
          hooks.getMethod("afterArchiveEntryName", String.class).invoke(null, paths[0]);
          methodName = "beforeFileWrite";
          parameters[0] = Object.class;
          arguments[0] = paths[1];
          break;
        case "jndiName":
          // Historical display text can be checked without instantiating a naming provider.
          java.lang.reflect.Field pattern = hooks.getDeclaredField("REMOTE_JNDI_LOOKUP");
          pattern.setAccessible(true);
          boolean remote = ((java.util.regex.Pattern) pattern.get(null)).matcher(value).find();
          System.out.println((remote ? "listed" : "unlisted") + "\t");
          continue;
        case "jndiRoute":
          int separator = value.indexOf('\0');
          if (separator < 0) throw new IllegalArgumentException("missing routing operation");
          methodName = "onJndiRoute";
          parameters = new Class<?>[]{String.class, String.class};
          arguments = new Object[]{value.substring(separator + 1), value.substring(0, separator)};
          break;
        case "beforeFileRead":
        case "beforeFileWrite":
          parameters[0] = Object.class;
          break;
        case "beforeFileUpload":
        case "beforeRuntimeExecString":
        case "beforeScriptEval":
        case "beforeH2JdbcConnection":
        case "beforeJdbcConnection":
          break;
        case "streamTypeName":
          // Report only the name predicate. Never resolve a class named by a historical input.
          boolean listed;
          try {
            Class<?> names = Class.forName("io.ohmyrasp.agent.serialization.StreamTypeNames");
            listed = (Boolean) names.getMethod("listed", String.class).invoke(null, value);
          } catch (ClassNotFoundException legacy) {
            java.lang.reflect.Field field = hooks.getDeclaredField("DESERIALIZATION_GADGET_CLASS");
            field.setAccessible(true);
            listed = ((java.util.regex.Pattern) field.get(null)).matcher(value).matches();
          }
          System.out.println((listed ? "listed" : "unlisted") + "\t");
          continue;
        case "beforeClassLoaderUrl":
        case "beforeRmiClassLoaderCodebase":
          if (methodName.equals("beforeClassLoaderUrl")) parameters[0] = Object.class;
          arguments[0] = value.split(" ", 3)[2];
          break;
        case "beforeXmlEntity":
          parameters = new Class<?>[]{String.class, Object.class};
          arguments = value.split(" ", 2);
          break;
        default: throw new IllegalArgumentException("unknown detector entry point");
      }
      Method method = hooks.getMethod(methodName, parameters);
      Files.deleteIfExists(log);
      boolean blocked = false;
      try {
        method.invoke(null, arguments);
        if ("beforeHttpRequest".equals(methodName)) hooks.getMethod("afterHttpRequest").invoke(null);
      } catch (InvocationTargetException failure) {
        if (!failure.getCause().getClass().getName().equals(prefix + "RaspBlockException")) {
          throw new IllegalStateException("detector failed: " + failure.getCause().getClass().getName());
        }
        blocked = true;
      }
      byte[] events = Files.exists(log) ? Files.readAllBytes(log) : new byte[0];
      System.out.println(blocked + "\t" + Base64.getEncoder().encodeToString(events));
    }
  }
}
