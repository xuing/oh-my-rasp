import java.lang.reflect.Proxy;
import java.util.Collections;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import io.ohmyrasp.agent.hook.OhMyRaspBlockException;
import io.ohmyrasp.agent.hook.OhMyRaspHooks;
import io.ohmyrasp.agent.policy.AgentPolicy;

/** Count actual application callbacks for a benign request and an operator-selected header policy. */
public class ServletAdmissionCheck extends HttpServlet {
  private int calls;
  private int redirects;
  private String note;
  private String output;
  private boolean personalData;
  private String mediaType;

  private boolean errorDispatch;
  private boolean dispatchNested;
  private boolean parametersUnavailable;
  private OhMyRaspBlockException parameterDenial;
  private String nestedUri = "/error";

  @Override protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, java.io.IOException {
    if (personalData) OhMyRaspHooks.beforeResponseDataLeak(mediaType, output);
    else if (output != null) OhMyRaspHooks.beforeXssEcho(output);
    calls++;
    if (note != null && !java.util.List.of(note).equals(OhMyRaspHooks.currentRequest().parameters().get("note")))
      throw new AssertionError("documentation text changed");
    if (parametersUnavailable) {
      if (!java.util.List.of("a b", "é", "\uFFFD", "+", "c").equals(OhMyRaspHooks.currentRequest().parameters().get("label")))
        throw new AssertionError("query parameters lost");
      try { request.getParameterMap(); throw new AssertionError("container exception lost"); }
      catch (IllegalStateException expected) { /* The application handles its upload limit. */ }
    }
    if (dispatchNested && !errorDispatch) {
      errorDispatch = true;
      try { service((ServletRequest) request, (ServletResponse) response); }
      finally { errorDispatch = false; }
    }
  }

  private void check(String agent, boolean deny, boolean redirectAvailable) throws Exception {
    HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> switch (method.getName()) {
          case "getMethod" -> "POST";
          case "getRequestURI" -> errorDispatch ? nestedUri : "/reports";
          case "getQueryString" -> parametersUnavailable ? "label=a+b&label=%FF&label=%C3%A9&label=%EF%BF%BD&label=%+1&label=%2B&label=c" : null;
          case "getHeaderNames" -> Collections.enumeration(Collections.singletonList("User-Agent"));
          case "getHeader" -> "User-Agent".equalsIgnoreCase((String) args[0]) ? agent : null;
          case "getParameterMap" -> note == null ? Collections.emptyMap() : Collections.singletonMap("note", new String[]{note});
          default -> null;
        });
    req = new HttpServletRequestWrapper(req) {
      @Override public String getRequestURI() { return super.getRequestURI(); }
      @Override public java.util.Map<String, String[]> getParameterMap() {
        if (parameterDenial != null) throw parameterDenial;
        if (parametersUnavailable) throw new IllegalStateException("upload exceeds configured limit");
        return super.getParameterMap();
      }
    };
    ServletResponse res = (ServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{HttpServletResponse.class}, (proxy, method, args) -> {
          if (method.getName().equals("getContentType")) return mediaType;
          if (method.getName().equals("sendRedirect")) {
            redirects++;
            if (!redirectAvailable) throw new IllegalStateException("response committed");
          }
          return null;
        });
    int previous = calls, previousRedirects = redirects;
    boolean rejected = false;
    try { service((ServletRequest) req, res); }
    catch (OhMyRaspBlockException blocked) {
      if (output != null && blocked.detection().request().active()) throw new AssertionError("response exception retained request");
      if (output != null && (blocked.detection().details().containsKey("value") || blocked.detection().details().containsKey("match")))
        throw new AssertionError("response exception retained content");
      if (parameterDenial != null && blocked != parameterDenial) throw new AssertionError("nested denial replaced");
      rejected = true;
    }
    if (rejected != (parameterDenial != null || (deny && (!redirectAvailable || output != null))) || calls != previous + (deny ? 0 : dispatchNested ? 2 : 1)
        || redirects != previousRedirects + (deny && parameterDenial == null ? 1 : 0) || OhMyRaspHooks.currentRequest().active())
      throw new AssertionError("unexpected dispatch: denied=" + rejected + ", calls=" + calls + ", redirects=" + redirects);
  }

  public static void main(String[] args) throws Exception {
    ServletAdmissionCheck servlet = new ServletAdmissionCheck();
    boolean block = args[0].equals("block");
    servlet.personalData = true;
    servlet.note = "4111 1111 1111 1111";
    servlet.output = "Example card: " + servlet.note;
    servlet.mediaType = "application/json";
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"hook\":\"response\",\"action\":\"block\"}]}"), "test");
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"response_dataLeak\",\"action\":\"block\"}]}"), "test");
    servlet.mediaType = "text/plain; profile=json";
    servlet.check("report-client", false, true);
    servlet.mediaType = "application/example+json; charset=UTF-8";
    servlet.check("report-client", block, true);
    servlet.personalData = false;
    servlet.note = null;
    OhMyRaspHooks.installPolicy(AgentPolicy.absent(), "");
    servlet.mediaType = "text/html";
    servlet.output = "<script src='/assets/report.js'></script>";
    servlet.check("report-client", false, true);
    servlet.note = "<script>";
    servlet.output = "Documentation: " + servlet.note;
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"xss_echo\",\"action\":\"block\"}]}"), "test");
    servlet.mediaType = "application/json";
    servlet.check("report-client", false, true);
    servlet.mediaType = "text/html; charset=UTF-8";
    servlet.output = "Documentation: &lt;script&gt;";
    servlet.check("report-client", false, true);
    servlet.output = "Documentation: " + servlet.note;
    servlet.check("report-client", block, true);
    servlet.output = null;
    OhMyRaspHooks.installPolicy(AgentPolicy.absent(), "");
    servlet.note = "The <script> element is documented here.";
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"hook\":\"request\",\"action\":\"block\"}]}"), "test");
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"xss_userinput\",\"action\":\"log\"}]}"), "test");
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"xss_userinput\",\"action\":\"block\"}]}"), "test");
    servlet.check("report-client", block, true);
    servlet.note = null;
    servlet.check("Nikto", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"request_scanner\",\"action\":\"block\"}]}"), "test");
    servlet.check("Nikto", block, true);
    servlet.check("Nikto", block, false);
    servlet.check("report-client", false, true);
    servlet.parametersUnavailable = true;
    servlet.check("report-client", false, true);
    servlet.check("Nikto", block, true);
    servlet.parametersUnavailable = false;
    servlet.parameterDenial = new OhMyRaspBlockException(null);
    servlet.check("report-client", true, false);
    servlet.parameterDenial = null;
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"request_scanner\",\"action\":\"log\"}]}"), "test");
    servlet.dispatchNested = true;
    servlet.check("Nikto", false, true);
    servlet.nestedUri = "/reports";
    servlet.check("Nikto", false, true);
  }
}
