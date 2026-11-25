import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.spark.deploy.rest.CreateSubmissionRequest;
import org.apache.spark.deploy.rest.CreateSubmissionResponse;
import org.apache.spark.deploy.rest.SubmitRequestServlet;
import org.apache.spark.deploy.rest.SubmitRestProtocolMessage;
import org.apache.spark.deploy.rest.SubmitRestProtocolResponse;

/** Run the Spark 2.3.1 servlet parser and validator. The handler only counts report submissions. */
public final class SparkReleaseServletCheck extends SubmitRequestServlet {
  private static final String REPORT = "{\"action\":\"CreateSubmissionRequest\",\"clientSparkVersion\":\"2.3.1\","
      + "\"appResource\":\"https://artifacts.example.invalid/weekly.jar\",\"mainClass\":\"reports.Weekly\","
      + "\"sparkProperties\":{\"spark.master\":\"local\",\"spark.app.name\":\"Weekly Report\"},"
      + "\"appArgs\":[],\"environmentVariables\":{}}";
  private int receipts;

  @Override public SubmitRestProtocolResponse handleSubmit(String descriptor, SubmitRestProtocolMessage message,
      HttpServletResponse response) {
    if (!(message instanceof CreateSubmissionRequest) || !"reports.Weekly".equals(((CreateSubmissionRequest) message).mainClass()))
      throw new AssertionError("unexpected parsed report");
    receipts++;
    return new CreateSubmissionResponse();
  }

  @Override public void sendResponse(SubmitRestProtocolResponse message, HttpServletResponse response) {
    if (!(message instanceof CreateSubmissionResponse)) throw new AssertionError("report rejected during validation");
  }

  private static HttpServletRequest request(boolean member) {
    ByteArrayInputStream bytes = new ByteArrayInputStream(REPORT.getBytes(StandardCharsets.UTF_8));
    ServletInputStream input = new ServletInputStream() {
      public int read() { return bytes.read(); }
      public boolean isReady() { return true; }
      public boolean isFinished() { return bytes.available() == 0; }
      public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
    };
    return (HttpServletRequest) Proxy.newProxyInstance(SparkReleaseServletCheck.class.getClassLoader(),
        new Class<?>[]{HttpServletRequest.class}, (proxy, method, args) -> {
          if ("getInputStream".equals(method.getName())) return input;
          if ("getRequestURI".equals(method.getName())) return "/reports/weekly";
          if ("isUserInRole".equals(method.getName())) {
            if (!"submitter".equals(args[0])) throw new AssertionError("unexpected role");
            return member;
          }
          return null;
        });
  }

  public static void main(String[] args) {
    SparkReleaseServletCheck servlet = new SparkReleaseServletCheck();
    HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(servlet.getClass().getClassLoader(),
        new Class<?>[]{HttpServletResponse.class}, (proxy, method, values) -> null);
    for (boolean member : new boolean[]{true, false}) {
      int before = servlet.receipts;
      boolean blocked = false;
      try {
        servlet.doPost(request(member), response);
      } catch (RuntimeException e) {
        if (!e.getClass().getSimpleName().endsWith("RaspBlockException")) throw e;
        blocked = true;
      }
      boolean expected = !member && "block".equals(args[0]);
      if (blocked != expected || servlet.receipts - before != (expected ? 0 : 1)) throw new AssertionError("handler receipt");
      System.out.println("member=" + member + " blocked=" + blocked + " receipts=" + (servlet.receipts - before));
    }
  }
}
