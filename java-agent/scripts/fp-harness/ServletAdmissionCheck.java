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

  private boolean errorDispatch;
  private boolean dispatchNested;
  private String nestedUri = "/error";

  @Override protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, java.io.IOException {
    calls++;
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
          case "getHeaderNames" -> Collections.enumeration(Collections.singletonList("User-Agent"));
          case "getHeader" -> "User-Agent".equalsIgnoreCase((String) args[0]) ? agent : null;
          case "getParameterMap" -> Collections.emptyMap();
          default -> null;
        });
    req = new HttpServletRequestWrapper(req) {
      @Override public String getRequestURI() { return super.getRequestURI(); }
      @Override public java.util.Map<String, String[]> getParameterMap() { return super.getParameterMap(); }
    };
    ServletResponse res = (ServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[]{HttpServletResponse.class}, (proxy, method, args) -> {
          if (method.getName().equals("sendRedirect")) {
            redirects++;
            if (!redirectAvailable) throw new IllegalStateException("response committed");
          }
          return null;
        });
    int previous = calls, previousRedirects = redirects;
    boolean rejected = false;
    try { service((ServletRequest) req, res); }
    catch (OhMyRaspBlockException blocked) { rejected = true; }
    if (rejected != (deny && !redirectAvailable) || calls != previous + (deny ? 0 : dispatchNested ? 2 : 1)
        || redirects != previousRedirects + (deny ? 1 : 0) || OhMyRaspHooks.currentRequest().active())
      throw new AssertionError("unexpected dispatch: denied=" + rejected + ", calls=" + calls + ", redirects=" + redirects);
  }

  public static void main(String[] args) throws Exception {
    ServletAdmissionCheck servlet = new ServletAdmissionCheck();
    boolean block = args[0].equals("block");
    servlet.check("Nikto", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"request_scanner\",\"action\":\"block\"}]}"), "test");
    servlet.check("Nikto", block, true);
    servlet.check("Nikto", block, false);
    servlet.check("report-client", false, true);
    OhMyRaspHooks.installPolicy(AgentPolicy.parse("{\"rules\":[{\"algorithm\":\"request_scanner\",\"action\":\"log\"}]}"), "test");
    servlet.dispatchNested = true;
    servlet.check("Nikto", false, true);
    servlet.nestedUri = "/reports";
    servlet.check("Nikto", false, true);
  }
}
