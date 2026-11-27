package io.ohmyrasp.playground.springbody;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * POST /ping takes a JSON object through Spring MVC's @RequestBody binding (Jackson reads the request's input
 * stream) and puts its "host" field into an inline shell program, as a ping page does.
 */
@SpringBootApplication
@RestController
public class SpringBodyApplication {
  public static void main(String[] args) {
    SpringApplication.run(SpringBodyApplication.class, args);
  }

  @GetMapping("/health")
  public String health() {
    return "ok";
  }

  @PostMapping("/ping")
  public String ping(@RequestBody Map<String, String> body) throws IOException, InterruptedException {
    Process process = new ProcessBuilder("sh", "-c", "echo " + body.get("host")).redirectErrorStream(true).start();
    String output = read(process.getInputStream());
    process.waitFor(5, TimeUnit.SECONDS);
    return output;
  }

  private static String read(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    for (int n; (n = in.read(buffer)) >= 0; ) out.write(buffer, 0, n);
    return new String(out.toByteArray(), StandardCharsets.UTF_8);
  }
}
