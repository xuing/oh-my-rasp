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
  public static final class PathOnlyRequest {
    private final String uri;

    PathOnlyRequest(String uri) { this.uri = uri; }

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
          arguments[0] = new PathOnlyRequest(value);
          break;
        case "archiveWrite":
          String[] paths = value.split(" -> ", -1);
          if (paths.length != 2) throw new IllegalArgumentException("ambiguous archive paths");
          hooks.getMethod("afterArchiveEntryName", String.class).invoke(null, paths[0]);
          methodName = "beforeFileWrite";
          parameters[0] = Object.class;
          arguments[0] = paths[1];
          break;
        case "beforeJndiLookup":
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
        case "beforeObjectStreamProxyResolve":
          // Both descriptor and proxy resolution call classifyDeserializationClass.
          // Submit the name to that classifier without loading the recorded class.
          parameters[0] = String[].class;
          arguments[0] = new String[]{value};
          break;
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
        if ("requestPath".equals(fields[0])) hooks.getMethod("afterHttpRequest").invoke(null);
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
