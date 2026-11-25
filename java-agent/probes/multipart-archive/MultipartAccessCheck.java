import java.io.InputStream;
import java.lang.reflect.*;
import java.util.*;
import javax.servlet.ServletContext;
import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.Part;

/** Reads metadata from inert report attachments. No uploaded code is run or installed. */
public class MultipartAccessCheck {
  public static class Request {
    String policy, path = "/import", dispatch = "REQUEST";
    boolean authorized;
    int roleCalls, iterations, sizeCalls;
    Part part;
    final ServletContext context = (ServletContext) Proxy.newProxyInstance(ServletContext.class.getClassLoader(),
        new Class<?>[]{ServletContext.class}, (proxy, method, args) -> method.getName().equals("getInitParameter")
            && "ohmyrasp.archiveUpload.POST/import".equals(args[0]) ? policy : null);
    final HttpServletRequest transport = (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> {
          switch (method.getName()) {
            case "getMethod": return "POST";
            case "getRequestURI": case "getServletPath": return path;
            case "getQueryString": return "";
            case "getHeaderNames": return Collections.enumeration(Collections.emptyList());
            case "getParameterMap": return Collections.emptyMap();
            case "getContentType": return "multipart/form-data; boundary=weekly";
            case "getDispatcherType": return DispatcherType.valueOf(dispatch);
            case "getServletContext": return context;
            case "isUserInRole": roleCalls++; return authorized && "operator".equals(args[0]);
            case "getPart": return part;
            case "getParts":
              return new AbstractCollection<Part>() {
                public int size() { sizeCalls++; return 1; }
                public Iterator<Part> iterator() {
                  iterations++;
                  return Collections.singletonList(part).iterator();
                }
              };
            default: return null;
          }
        });
  }

  public static class Named {
    final String value;
    int calls;
    Named(String value) { this.value = value; }
    public String getSubmittedFileName() { calls++; return value; }
    public String getOriginalFilename() { calls++; return value; }
  }

  public static class Attachment extends Named implements Part {
    Attachment(String value) { super(value); }
    public String getName() { return "metadata.jar"; }  // multipart field name
    public String getContentType() { return "application/octet-stream"; }
    public long getSize() { return 0; }
    public InputStream getInputStream() { return new java.io.ByteArrayInputStream(new byte[0]); }
    public void write(String name) { throw new UnsupportedOperationException(); }
    public void delete() { }
    public String getHeader(String name) { return null; }
    public Collection<String> getHeaders(String name) { return Collections.emptyList(); }
    public Collection<String> getHeaderNames() { return Collections.emptyList(); }
  }
  public static class Delegating extends Attachment {
    Delegating(String name) { super(name); }
    @Override public String getSubmittedFileName() { return super.getSubmittedFileName(); }
  }
  public static class Rejecting extends Attachment {
    Rejecting() { super("weekly.jar"); }
    @Override public String getSubmittedFileName() { throw new IllegalStateException("catalog unavailable"); }
  }

  static Class<?> hooks;
  static boolean primary;
  static void track(String id) throws Exception {
    primary = id.equals("main");
    hooks = id.equals("off") ? null : Class.forName(primary ? "io.ohmyrasp.agent.hook.OhMyRaspHooks" :
        "io.ohmyrasp.agent.java" + id + ".Java" + id + "RaspHooks");
  }
  static void enter(Request request) throws Exception {
    if (hooks == null) return;
    if (primary) hooks.getMethod("enterHttpRequest", Object.class, Object.class).invoke(null, request.transport, null);
    else hooks.getMethod("beforeHttpRequest", Object.class).invoke(null, request.transport);
  }
  static void exit() throws Exception { if (hooks != null) hooks.getMethod(primary ? "exitHttpRequest" : "afterHttpRequest").invoke(null); }

  interface Name { String read() throws Exception; }
  static void check(Request request, String mode, String label, boolean policy, String value, Name read) throws Exception {
    boolean denied = false;
    enter(request);
    try {
      if (request.part != null) request.transport.getPart("attachment");
      if (!Objects.equals(value, read.read())) throw new AssertionError("wrong returned name in " + label);
    } catch (Exception e) {
      if (!HttpTransportCheck.blocked(e)) throw e;
      denied = true;
    } finally { exit(); }
    System.out.println("row," + label + "," + policy + "," + denied);
    if (!mode.equals("observe") && denied != (mode.equals("block") && policy)) throw new AssertionError(label);
  }

  public static void main(String[] args) throws Exception {
    track(args[0]);
    String mode = args[1];
    int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    for (int n = 0; n < rounds; n++) {
      Request req = new Request();
      String name = "report-" + n + ".jar";
      Attachment file = new Delegating(name);
      req.part = file;
      check(req, mode, "unconfigured", false, name, file::getSubmittedFileName);
      if (req.roleCalls != 0) throw new AssertionError("role queried on unconfigured route");
      req.policy = "role:operator"; req.authorized = true;
      check(req, mode, "authorized", false, name, file::getSubmittedFileName);
      req.authorized = false;
      check(req, mode, "delegated-denial", true, name, file::getSubmittedFileName);
      req.authorized = true;
      check(req, mode, "authorization-refreshed", false, name, file::getSubmittedFileName);
      if (file.calls != 4) throw new AssertionError("agent reread the application getter");
      req.policy = "deny";
      Attachment inherited = new Attachment(name);
      req.part = inherited;
      check(req, mode, "inherited", true, name, inherited::getSubmittedFileName);
      check(req, mode, "form-field-name", false, "metadata.jar", inherited::getName);
      check(req, mode, "unrelated-method-on-part", false, name, inherited::getOriginalFilename);
      Named other = new Named(name);
      check(req, mode, "same-base-other-object", false, name, other::getSubmittedFileName);
      check(req, mode, "ordinary-document", false, "weekly.html", new Attachment("weekly.html")::getSubmittedFileName);
      Attachment spaced = new Attachment("weekly.jar ");
      req.part = spaced;
      check(req, mode, "space-in-name", false, "weekly.jar ", spaced::getSubmittedFileName);
      check(req, mode, "form-field", false, null, new Attachment(null)::getSubmittedFileName);
      Part proxy = (Part) Proxy.newProxyInstance(Part.class.getClassLoader(), new Class<?>[]{Part.class},
          (self, method, values) -> method.getName().equals("getSubmittedFileName") ? name : null);
      req.part = proxy;
      check(req, mode, "proxy", true, name, proxy::getSubmittedFileName);
      req.path = "/import/status";
      check(req, mode, "neighbor", false, name, proxy::getSubmittedFileName);
      req.path = "/import"; req.dispatch = "INCLUDE";
      check(req, mode, "ambiguous-dispatch", false, name, inherited::getSubmittedFileName);
      req.dispatch = "REQUEST";
      enter(req);
      try {
        new Rejecting().getSubmittedFileName();
        throw new AssertionError("missing application exception");
      } catch (IllegalStateException expected) {
        if (!"catalog unavailable".equals(expected.getMessage())) throw expected;
      } finally { exit(); }
      req.part = inherited;
      check(req, mode, "after-exception", true, name, inherited::getSubmittedFileName);

      Attachment internal = new Attachment(name) {
        @Override public int hashCode() { throw new AssertionError("application hashCode called"); }
        @Override public boolean equals(Object other) { throw new AssertionError("application equality called"); }
      };
      check(req, mode, "unsubmitted-part", false, name, internal::getSubmittedFileName);
      Request another = new Request();
      another.part = internal;
      check(req, mode, "other-request", false, name, () -> another.transport.getPart("attachment").getSubmittedFileName());
      HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(req.transport);
      req.part = null;
      check(req, mode, "wrapped-request", true, name, () -> {
        req.part = internal;
        return wrapper.getPart("attachment").getSubmittedFileName();
      });
      req.part = null;
      class Covariant extends HttpServletRequestWrapper {
        Covariant(HttpServletRequest original) { super(original); }
        @Override public Attachment getPart(String ignored) { return internal; }
      }
      Covariant covariant = new Covariant(req.transport);
      check(req, mode, "covariant-lookup", true, name, () -> covariant.getPart("attachment").getSubmittedFileName());
      check(req, mode, "lazy-bulk", true, name, () -> {
        req.part = internal;
        return req.transport.getParts().iterator().next().getSubmittedFileName();
      });
      if (req.iterations != 1 || req.sizeCalls != 0) throw new AssertionError("extra bulk collection access");
      req.part = null;
      check(req, mode, "bulk-not-consumed", false, name, () -> {
        req.part = internal;
        req.transport.getParts();
        return internal.getSubmittedFileName();
      });
    }
  }
}
