package io.ohmyrasp.playground.java17;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Request-body endpoints for java-agent/acceptance/runtime/request-body.sh: each reads its JSON body the way an
 * application does, through the container's input stream or its reader, and uses a field of it.
 *
 * <ul>
 * <li>POST /body/ping: the "host" field, read through getInputStream(), goes into an inline shell program.</li>
 * <li>POST /body/ping-reader: the same, read through getReader().</li>
 * <li>PATCH /body/patch: reads a JSON Patch document and applies nothing.</li>
 * <li>POST /body/size: reads the body and reports its length and how long the read loop took on the request
 *     thread (java-agent/acceptance/runtime/request-body-cost.sh).</li>
 * </ul>
 */
@WebServlet(urlPatterns = "/body/*")
public final class RequestBodyServlet extends HttpServlet {
  private static final Pattern HOST = Pattern.compile("\"host\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");

  @Override
  protected void service(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String path = request.getPathInfo() == null ? "/" : request.getPathInfo();
    if ("PATCH".equals(request.getMethod()) && "/patch".equals(path)) {
      String body = new String(readAll(request.getInputStream()), charset(request));
      send(response, "patched " + body.length() + " chars");
      return;
    }
    if ("/size".equals(path)) {
      InputStream in = request.getInputStream();
      byte[] buffer = new byte[8192];
      long total = 0;
      long started = System.nanoTime();
      for (int n; (n = in.read(buffer)) >= 0; ) total += n;
      long elapsed = System.nanoTime() - started;
      send(response, "bytes=" + total + " read_ns=" + elapsed);
      return;
    }
    if ("GET".equals(request.getMethod()) && "/health".equals(path)) {
      send(response, "ok");
      return;
    }
    if (!"POST".equals(request.getMethod())) {
      response.sendError(405);
      return;
    }
    String body;
    if ("/ping".equals(path)) {
      body = new String(readAll(request.getInputStream()), charset(request));
    } else if ("/ping-reader".equals(path)) {
      body = readAll(request.getReader());
    } else {
      response.sendError(404);
      return;
    }
    Matcher host = HOST.matcher(body);
    if (!host.find()) {
      response.sendError(400, "no host");
      return;
    }
    send(response, ping(host.group(1).replace("\\\"", "\"").replace("\\\\", "\\")));
  }

  private static String ping(String host) throws IOException {
    Process process = new ProcessBuilder("sh", "-c", "echo " + host).redirectErrorStream(true).start();
    byte[] output = readAll(process.getInputStream());
    try {
      process.waitFor(5, TimeUnit.SECONDS);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
    }
    return new String(output, StandardCharsets.UTF_8);
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    for (int n; (n = in.read(buffer)) >= 0; ) out.write(buffer, 0, n);
    return out.toByteArray();
  }

  private static String readAll(Reader in) throws IOException {
    StringBuilder out = new StringBuilder();
    char[] buffer = new char[1024];
    for (int n; (n = in.read(buffer)) >= 0; ) out.append(buffer, 0, n);
    return out.toString();
  }

  private static Charset charset(HttpServletRequest request) {
    String name = request.getCharacterEncoding();
    return name == null ? StandardCharsets.UTF_8 : Charset.forName(name);
  }

  private static void send(HttpServletResponse response, String text) throws IOException {
    response.setContentType("text/plain;charset=UTF-8");
    response.getWriter().write(text);
  }
}
