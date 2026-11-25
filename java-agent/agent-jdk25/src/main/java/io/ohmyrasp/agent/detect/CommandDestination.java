package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.net.NetworkHost;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Reads literal network operands from direct launches, without executing or resolving anything. */
final class CommandDestination {
  private static final Set<String> CURL_VALUES = Set.of(
      "-o", "--output", "-H", "--header", "-d", "--data", "--data-binary", "-X", "--request",
      "--connect-timeout", "--max-time");
  private static final Set<String> WGET_VALUES = Set.of("-O", "--output-document", "--header", "-T", "--timeout");
  private static final Set<String> CURL_SWITCHES = Set.of(
      "--disable", "--silent", "--fail", "--show-error", "--location", "--head", "--insecure");
  private static final Set<String> WGET_SWITCHES = Set.of("--quiet", "--server-response");
  private static final Pattern PING_COUNT = Pattern.compile("[1-9][0-9]{0,8}");
  private static final Pattern CURL_FLAGS = Pattern.compile("-[qfsSLIk]+");
  private static final Pattern WGET_FLAGS = Pattern.compile("-[qS]+");

  private CommandDestination() {}

  static String callbackHost(List<String> argv) {
    if (argv.size() < 2 || argv.get(0) == null) return null;
    String executable = new File(argv.get(0)).getName();
    if (File.separatorChar == '\\') {
      executable = executable.toLowerCase(Locale.ROOT);
      if (executable.endsWith(".exe")) executable = executable.substring(0, executable.length() - 4);
    }
    return switch (executable) {
      case "curl", "wget" -> transfer(argv, executable.equals("curl"));
      case "ping", "nslookup", "dig" -> lookup(argv, executable);
      default -> null;
    };
  }

  private static String lookup(List<String> argv, String tool) {
    String host = argv.get(argv.size() - 1);
    if (host == null || host.startsWith("-") || host.startsWith("[")) return null;
    if (argv.size() == 2) return listed(host);
    if (tool.equals("ping") && argv.size() == 4 && "-c".equals(argv.get(1))
        && File.separatorChar == '/' && argv.get(2) != null && PING_COUNT.matcher(argv.get(2)).matches()) {
      return listed(host);
    }
    return null;
  }

  private static String transfer(List<String> argv, boolean curl) {
    String destination = null;
    boolean options = true;
    for (int i = 1; i < argv.size(); i++) {
      String arg = argv.get(i);
      if (arg == null || arg.isEmpty()) return null;
      if (options && arg.startsWith("-")) {
        if (arg.equals("--")) {
          options = false;
          continue;
        }
        if ((curl ? CURL_VALUES : WGET_VALUES).contains(arg)) {
          if (++i >= argv.size() || argv.get(i) == null) return null;
          continue;
        }
        if (curl && arg.equals("--url") && i + 1 < argv.size()) {
          arg = argv.get(++i);
        } else if ((curl ? CURL_SWITCHES : WGET_SWITCHES).contains(arg)
            || (curl ? CURL_FLAGS : WGET_FLAGS).matcher(arg).matches()) {
          continue;
        } else {
          // Other option grammars may consume following arguments or suppress the transfer.
          return null;
        }
      }
      if (destination == null) destination = transferHost(arg);
    }
    return destination;
  }

  private static String transferHost(String operand) {
    if (operand == null || operand.isEmpty() || operand.startsWith("/") || operand.startsWith("-")) return null;
    try {
      URI uri = new URI(operand.contains("://") ? operand : "http://" + operand);
      if ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())
          || "ftp".equalsIgnoreCase(uri.getScheme())) return listed(uri.getHost());
    } catch (URISyntaxException invalid) {
      // Only literal authorities supply process-level destination evidence.
    }
    return null;
  }

  private static String listed(String host) {
    String normalized = NetworkHost.normalize(host);
    return CallbackDomain.matches(normalized) ? normalized : null;
  }
}
