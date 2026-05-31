package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

public final class DetectorEngine {
  private static final Pattern SQLI_USER_INPUT =
      Pattern.compile(
          "(?is)(?:'\\s*(?:or|and)\\s+(?:\\d+\\s*=\\s*\\d+|'[^']*'\\s*=\\s*'[^']*')|union\\s+select|--|/\\*|;\\s*(?:select|insert|update|delete|drop|alter)\\b)");
  private static final Pattern SQL_POLICY =
      Pattern.compile(
          "(?is)(?:\\bunion\\s+(?:all\\s+)?select\\b|\\binformation_schema\\b|\\binto\\s+(?:out|dump)file\\b|/\\*!|\\bload_file\\s*\\(|\\bsleep\\s*\\(|\\bbenchmark\\s*\\()");
  private static final Pattern COMMAND_COMMON =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/passwd|nc\\b.{0,40}\\s-e\\s+/bin/(?:ba)?sh|bash\\s+-i\\b|/dev/tcp/|curl\\b.{0,80}\\|\\s*(?:sh|bash)|wget\\b.{0,80}\\|\\s*(?:sh|bash)|\\{echo,.{10,400}\\}\\|\\{base64,-d\\})");
  private static final Pattern COMMAND_META = Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");
  private static final Pattern COMMAND_SENSITIVE_AFTER_JOIN =
      Pattern.compile("(?is)(?:;|&&|\\|\\|?|`)\\s*(?:cat|bash|sh|nc|curl|wget|python|perl|php)\\b");
  private static final Pattern COMMAND_DNSLOG =
      Pattern.compile("(?is)(^|\\W)(curl|ping|wget|nslookup|dig)\\W.*");
  private static final Pattern DANGEROUS_FILE_READ =
      Pattern.compile(
          "(?is)(?:^|/)(?:etc/(?:issue|passwd|shadow|apache2/apache2\\.conf)|proc/self/environ|root/\\.ssh|root/\\.bash_(?:history|profile)|\\.bash_history|\\.zsh_history|\\.mysql_history|id_rsa|windows/system32/(?:inetsrv/metabase\\.xml|drivers/etc/hosts))$");
  private static final Pattern SCRIPT_FILE =
      Pattern.compile("(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)\\.?$");
  private static final Pattern CLEAN_FILE =
      Pattern.compile("(?is).+\\.(?:jpg|jpeg|png|gif|bmp|txt|rar|zip)$");
  private static final Pattern HTML_FILE = Pattern.compile("(?is).+\\.(?:htm|html|js)$");
  private static final Pattern EXECUTABLE_FILE =
      Pattern.compile("(?is).+\\.(?:exe|dll|scr|vbs|cmd|bat)$");
  private static final Pattern NTFS_STREAM = Pattern.compile("(?is).*::\\$(?:data|index)$");
  private static final Pattern READ_SAFE_EXTENSION =
      Pattern.compile(
          "(?is).+\\.(?:docx?|dotx?|docm|dotm|xlsx?|xltx?|xlsm|xlsb|pptx?|ppsx?|ppsm|potx?|potm|7z|tar|gz|bz2|xz|rar|zip|jpe?g|png|gif|bmp|txt)$");
  private static final Pattern DNSLOG_DOMAIN =
      Pattern.compile(
          "(?i).*((?:ceye|exeye|sslip|nip)\\.io|dnslog\\.cn|(?:vcap|bxss)\\.me|xip\\.(?:name|io)|burpcollaborator\\.net|tu4\\.org|2xss\\.cc|request\\.bin|requestbin\\.net|pipedream\\.net|canarytokens\\.com)$");
  private static final Pattern DNSLOG_TEXT =
      Pattern.compile(
          "(?i).*((?:ceye|exeye|sslip|nip)\\.io|dnslog\\.cn|(?:vcap|bxss)\\.me|xip\\.(?:name|io)|burpcollaborator\\.net|tu4\\.org|2xss\\.cc|request\\.bin|requestbin\\.net|pipedream\\.net|canarytokens\\.com)(?:[/:?].*)?");
  private static final Pattern XSS_INPUT =
      Pattern.compile("(?is)<![-\\[]|<([A-Za-z]{1,12})[/>\\x00-\\x20]");
  private static final Pattern CHINA_ID =
      Pattern.compile("(?<!\\d)\\d{10}(?:[01]\\d)(?:[0123]\\d)\\d{3}(?:\\d|x|X)(?!\\d)");
  private static final Pattern CHINA_MOBILE =
      Pattern.compile("(?<!\\w)(?:(?:00|\\+)?86 ?)?(1\\d{2})(?:[ -]?\\d){8}(?!\\w)");
  private static final Pattern BANK_CARD =
      Pattern.compile("(?<!\\d)(?:62|3|5[1-5]|4\\d)\\d{2}(?:[ -]?\\d{4}){3}(?!\\d)");

  private static final Set<String> SSRF_PROTOCOLS =
      Set.of("file", "gopher", "dict", "ftp", "ldap", "jar", "netdoc");
  private static final Set<String> INCLUDE_PROTOCOLS =
      Set.of(
          "file",
          "gopher",
          "jar",
          "netdoc",
          "http",
          "https",
          "dict",
          "php",
          "compress.zlib",
          "compress.bzip2",
          "zip",
          "rar");
  private static final Set<String> SCANNER_MARKERS =
      Set.of(
          "sqlmap",
          "nikto",
          "nessus",
          "arachni",
          "webinspect",
          "acunetix",
          "appscan",
          "w3af",
          "masscan",
          "nmap",
          "zgrab",
          "dirbuster");
  private static final Set<String> DESERIALIZATION_BLACKLIST =
      Set.of(
          "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
          "org.apache.commons.collections.functors.InvokerTransformer",
          "org.apache.commons.collections4.functors.InvokerTransformer",
          "org.codehaus.groovy.runtime.ConvertedClosure",
          "org.springframework.beans.factory.ObjectFactory",
          "javax.management.BadAttributeValueExpException",
          "io.ohmyrasp.playground.EvilSerialized");
  private static final Set<String> OGNL_BLACKLIST =
      Set.of(
          "ognl.OgnlContext",
          "ognl.TypeConverter",
          "ognl.MemberAccess",
          "_memberAccess",
          "ognl.ClassResolver",
          "java.lang.Runtime",
          "java.lang.Class",
          "java.lang.ClassLoader",
          "java.lang.System",
          "java.lang.ProcessBuilder",
          "java.lang.Object",
          "java.lang.Shutdown",
          "java.io.File",
          "javax.script.ScriptEngineManager",
          "excludedClasses",
          "excludedPackageNamePatterns",
          "excludedPackageNames",
          "com.opensymphony.xwork2.ActionContext");
  private static final Set<String> WEBSHELL_CALLABLES =
      Set.of("system", "exec", "passthru", "proc_open", "shell_exec", "popen", "pcntl_exec", "assert");
  private static final Set<String> WEBSHELL_ENV =
      Set.of("LD_PRELOAD", "LD_AUDIT", "GCONV_PATH");
  private static final Set<String> CHINA_MOBILE_PREFIXES =
      Set.of(
          "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "145",
          "146", "147", "148", "149", "150", "151", "152", "153", "155", "156", "157",
          "158", "159", "165", "166", "170", "173", "174", "175", "176", "177", "178",
          "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "198",
          "199");

  public Optional<Detection> detectRequest(RequestContext request) {
    String userAgent = request.header("user-agent").orElse("").toLowerCase(Locale.ROOT);
    for (String marker : SCANNER_MARKERS) {
      if (userAgent.contains(marker)) {
        return Optional.of(
            Detection.log(
                "request",
                "request_scanner",
                90,
                "Scanner-like user agent detected: " + marker,
                request,
                Map.of("userAgent", userAgent)));
      }
    }
    if (userAgent.isBlank()) {
      return Optional.of(
          Detection.log(
              "request",
              "request_unusual",
              50,
              "HTTP request missing User-Agent",
              request,
              Map.of()));
    }
    for (String value : request.allParameterValues()) {
      if (value != null && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "request",
                "xss_userinput",
                70,
                "XSS-like request parameter detected",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectSql(String query, RequestContext request) {
    if (query == null || query.isBlank()) {
      return Optional.empty();
    }
    if (request.hasParameterIn(query) && SQLI_USER_INPUT.matcher(query).find()) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_userinput",
              95,
              "SQL query structure appears altered by request input",
              request,
              Map.of("query", abbreviate(query))));
    }
    if (SQL_POLICY.matcher(query).find()) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_policy",
              85,
              "SQL query matched injection policy features",
              request,
              Map.of("query", abbreviate(query))));
    }
    if (query.toLowerCase(Locale.ROOT).contains("information_schema")) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_regex",
              60,
              "SQL query matched configured regex",
              request,
              Map.of("query", abbreviate(query))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectSqlException(
      String server,
      String errorCode,
      String errorState,
      String errorMessage,
      String query,
      RequestContext request) {
    String normalizedServer = lower(server);
    String normalizedCode = errorCode == null ? "" : errorCode.trim();
    String normalizedState = errorState == null ? "" : errorState.trim().toUpperCase(Locale.ROOT);
    String normalizedMessage = lower(errorMessage);
    String normalizedQuery = query == null ? "" : query;
    if (!isSqlExceptionSignal(
        normalizedServer, normalizedCode, normalizedState, normalizedMessage, normalizedQuery)) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "sql_exception",
            "sql_exception",
            70,
            "Database error signal detected: " + normalizedServer + " " + normalizedCode,
            request,
        Map.of(
                "server", normalizedServer,
                "errorCode", normalizedCode,
                "errorState", normalizedState,
                "message", abbreviate(errorMessage),
                "query", abbreviate(query))));
  }

  public Optional<Detection> detectSqlRegex(
      String query, String regex, RequestContext request) {
    if (query == null || query.isBlank() || regex == null || regex.isBlank()) {
      return Optional.empty();
    }
    if (Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(query).find()) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_regex",
              60,
              "SQL query matched configured regex",
              request,
              Map.of("query", abbreviate(query), "regex", regex)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectCommand(List<String> command, RequestContext request) {
    return detectCommand(command, request, List.of());
  }

  public Optional<Detection> detectCommand(
      List<String> command, RequestContext request, List<String> stackClassNames) {
    String joined = command == null ? "" : String.join(" ", command);
    if (joined.isBlank()) {
      return Optional.empty();
    }
    if (stackLooksReflective(stackClassNames)) {
      return Optional.of(
          Detection.log(
              "command",
              "command_reflect",
              90,
              "Command execution reached from reflective or generated code",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (request.hasParameterIn(joined) && COMMAND_META.matcher(joined).find()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_userinput",
              95,
              "Command contains request input and shell metacharacters",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (COMMAND_COMMON.matcher(joined).find()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_common",
              95,
              "Potentially dangerous command execution detected",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (COMMAND_DNSLOG.matcher(joined).find() && DNSLOG_TEXT.matcher(joined).matches()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_dnslog",
              95,
              "Command targets a callback collection domain",
              request,
              Map.of("command", abbreviate(joined))));
    }
    if (COMMAND_SENSITIVE_AFTER_JOIN.matcher(joined).find()
        || hasUnbalancedQuotes(joined)
        || joined.contains("$IFS")
        || joined.contains("${IFS}")) {
      return Optional.of(
          Detection.log(
              "command",
              "command_error",
              75,
              "Command contains suspicious shell syntax",
              request,
              Map.of("command", abbreviate(joined))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectUrl(String rawUrl, RequestContext request) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(rawUrl);
    } catch (IllegalArgumentException e) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              70,
              "Malformed outbound URL detected",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    String scheme = lower(uri.getScheme());
    String host = lower(uri.getHost());
    String path = lower(uri.getPath());
    if (isLocalClasspathResource(rawUrl, scheme, path)) {
      return Optional.empty();
    }
    if (!request.active() && ("file".equals(scheme) || "jar".equals(scheme))) {
      return Optional.empty();
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              90,
              "Outbound request uses a dangerous protocol: " + scheme,
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    if (host.contains("169.254.169.254") || path.contains("/latest/meta-data")) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "Outbound request targets cloud instance metadata",
              request,
              Map.of("url", abbreviate(rawUrl))));
    }
    if (isInternalHost(host) || request.hasParameterIn(rawUrl)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_userinput",
              90,
              "Outbound request targets an internal or user-controlled address",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (DNSLOG_DOMAIN.matcher(host).matches()) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "Outbound request targets a callback collection domain",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              80,
              "Outbound request host appears obfuscated",
              request,
              Map.of("url", abbreviate(rawUrl), "host", host)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectDns(String host, RequestContext request) {
    if (host == null || host.isBlank()) {
      return Optional.empty();
    }
    String normalized = lower(host);
    if (DNSLOG_DOMAIN.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "dns",
              "dns_blacklist",
              95,
              "DNS lookup targets a callback collection domain",
              request,
              Map.of("host", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectFileRead(String path, RequestContext request, boolean xmlParserStack) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    if (xmlParserStack && DANGEROUS_FILE_READ.matcher(normalized).find()) {
      return Optional.of(
          Detection.log(
              "xxe",
              "xxe_file",
              90,
              "XML parser attempted to read a sensitive local file",
              request,
              Map.of("path", normalized)));
    }
    if (!request.active()) {
      return Optional.empty();
    }
    String protocol = protocolOf(path);
    if (request.hasParameterIn(path) || request.hasParameterIn(normalized)) {
      if (protocol.equals("http") || protocol.equals("https")) {
        return Optional.of(
            Detection.log(
                "readFile",
                "readFile_userinput_http",
                90,
                "File streaming function requested an HTTP resource from user input",
                request,
                Map.of("path", abbreviate(path))));
      }
      if (protocol.equals("file") || protocol.equals("php")) {
        return Optional.of(
            Detection.log(
                "readFile",
                "readFile_userinput_unwanted",
                90,
                "File read used an unwanted user-controlled protocol",
                request,
                Map.of("path", abbreviate(path), "protocol", protocol)));
      }
      if (READ_SAFE_EXTENSION.matcher(normalized).matches()) {
        return Optional.empty();
      }
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_userinput",
              90,
              "File read path is controlled by request input",
              request,
              Map.of("path", normalized)));
    }
    if (DANGEROUS_FILE_READ.matcher(normalized).find()) {
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_unwanted",
              85,
              "Sensitive local file read detected",
              request,
              Map.of("path", normalized)));
    }
    if (normalized.startsWith("/etc/")
        || normalized.startsWith("/proc/")
        || normalized.startsWith("/root/")) {
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_outsideWebroot",
              65,
              "File read appears outside the web root",
              request,
              Map.of("path", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectFileWrite(String path, RequestContext request) {
    return detectFileWrite(path, request, List.of());
  }

  public Optional<Detection> detectFileWrite(
      String path, RequestContext request, List<String> stackClassNames) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    if (NTFS_STREAM.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_NTFS",
              90,
              "NTFS alternate data stream write detected",
              request,
              Map.of("path", normalized)));
    }
    if (stackLooksReflective(stackClassNames)
        && (normalized.endsWith(".jsp") || normalized.endsWith(".jspx"))) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_reflect",
              85,
              "Reflective stack wrote a JSP file",
              request,
              Map.of("path", normalized)));
    }
    if (SCRIPT_FILE.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_script",
              90,
              "Server-side script file write detected",
              request,
              Map.of("path", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectFileDelete(String path, RequestContext request) {
    String normalized = normalizePath(path);
    if (!normalized.isBlank() && request.hasParameterIn(normalized)) {
      return Optional.of(
          Detection.log(
              "deleteFile",
              "deleteFile_userinput",
              80,
              "File delete path is controlled by request input",
              request,
              Map.of("path", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectDirectoryList(String path, RequestContext request) {
    return detectDirectoryList(path, request, List.of());
  }

  public Optional<Detection> detectDirectoryList(
      String path, RequestContext request, List<String> stackClassNames) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    if (stackLooksReflective(stackClassNames)) {
      return Optional.of(
          Detection.log(
              "directory",
              "directory_reflect",
              90,
              "Reflective stack listed a directory",
              request,
              Map.of("path", normalized)));
    }
    if (request.hasParameterIn(normalized)) {
      return Optional.of(
          Detection.log(
              "directory",
              "directory_userinput",
              85,
              "Directory listing path is controlled by request input",
              request,
              Map.of("path", normalized)));
    }
    if (normalized.equals("/etc") || normalized.equals("/proc") || normalized.equals("/root")) {
      return Optional.of(
          Detection.log(
              "directory",
              "directory_unwanted",
              70,
              "Sensitive directory listing detected",
              request,
              Map.of("path", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectInclude(
      String url, String realPath, String function, RequestContext request) {
    String target = url == null ? "" : url;
    if (target.isBlank()) {
      return Optional.empty();
    }
    if (request.hasParameterIn(target) || request.hasParameterIn(realPath)) {
      return Optional.of(
          Detection.log(
              "include",
              "include_userinput",
              100,
              "File inclusion target is controlled by request input",
              request,
              Map.of("url", abbreviate(target), "realPath", abbreviate(realPath))));
    }
    String protocol = protocolOf(target);
    if (INCLUDE_PROTOCOLS.contains(protocol)) {
      return Optional.of(
          Detection.log(
              "include",
              "include_protocol",
              90,
              "File inclusion used an unwanted protocol: " + protocol,
              request,
              Map.of("url", abbreviate(target), "function", String.valueOf(function))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectFileUpload(String filename, RequestContext request) {
    String normalized = normalizePath(filename);
    if (normalized.isBlank()) {
      return Optional.empty();
    }
    if (SCRIPT_FILE.matcher(normalized).matches()
        || NTFS_STREAM.matcher(normalized).matches()
        || normalized.endsWith("/.htaccess")
        || normalized.endsWith("/.user.ini")
        || normalized.equals(".htaccess")
        || normalized.equals(".user.ini")) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_script",
              95,
              "Multipart upload contains a server-side script or config file",
              request,
              Map.of("filename", normalized)));
    }
    if (HTML_FILE.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_html",
              90,
              "Multipart upload contains an HTML or JavaScript file",
              request,
              Map.of("filename", normalized)));
    }
    if (EXECUTABLE_FILE.matcher(normalized).matches()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_exe",
              90,
              "Multipart upload contains an executable file",
              request,
              Map.of("filename", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebdavUpload(
      String source, String destination, String method, RequestContext request) {
    String normalizedSource = normalizePath(source);
    String normalizedDestination = normalizePath(destination);
    if (!SCRIPT_FILE.matcher(normalizedSource).matches()
        && SCRIPT_FILE.matcher(normalizedDestination).matches()) {
      return Optional.of(
          Detection.log(
              "webdav",
              "fileUpload_webdav",
              100,
              "WebDAV-style move produced a server-side script file",
              request,
              Map.of(
                  "source", normalizedSource,
                  "destination", normalizedDestination,
                  "method", String.valueOf(method))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectRename(String source, String destination, RequestContext request) {
    if (CLEAN_FILE.matcher(normalizePath(source)).matches()
        && SCRIPT_FILE.matcher(normalizePath(destination)).matches()) {
      return Optional.of(
          Detection.log(
              "rename",
              "rename_webshell",
              90,
              "Rename converted a non-script file into a server-side script",
              request,
              Map.of("source", normalizePath(source), "destination", normalizePath(destination))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectLink(
      String source, String destination, String type, RequestContext request) {
    if (CLEAN_FILE.matcher(normalizePath(source)).matches()
        && SCRIPT_FILE.matcher(normalizePath(destination)).matches()) {
      return Optional.of(
          Detection.log(
              "link",
              "link_webshell",
              90,
              "Link converted a non-script file into a server-side script",
              request,
              Map.of(
                  "source", normalizePath(source),
                  "destination", normalizePath(destination),
                  "type", String.valueOf(type))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectJndi(String name, RequestContext request) {
    if (name == null || name.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "jndi",
            "jndi_disable_all",
            100,
            "JNDI lookup intercepted",
            request,
            Map.of("name", abbreviate(name))));
  }

  public Optional<Detection> detectDeserialization(String className, RequestContext request) {
    if (className == null || className.isBlank()) {
      return Optional.empty();
    }
    if (DESERIALIZATION_BLACKLIST.contains(className)) {
      return Optional.of(
          Detection.log(
              "deserialization",
              "deserialization_blacklist",
              100,
              "Deserialization blacklist matched class " + className,
              request,
              Map.of("class", className)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectOgnl(String expression, RequestContext request) {
    if (expression == null || expression.isBlank()) {
      return Optional.empty();
    }
    for (String item : OGNL_BLACKLIST) {
      if (expression.contains(item)) {
        return Optional.of(
            Detection.log(
                "ognl",
                "ognl_blacklist",
                100,
                "OGNL expression contains a dangerous class or object reference",
                request,
                Map.of("match", item, "expression", abbreviate(expression))));
      }
    }
    if (expression.length() > 400) {
      return Optional.of(
          Detection.log(
              "ognl",
              "ognl_length_limit",
              100,
              "OGNL expression length is unusual: " + expression.length(),
              request,
              Map.of("length", String.valueOf(expression.length()))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectEval(String function, String code, RequestContext request) {
    if (code == null || code.isBlank()) {
      return Optional.empty();
    }
    if (Pattern.compile("(?is)base64_decode|gzuncompress|create_function").matcher(code).find()) {
      return Optional.of(
          Detection.log(
              "eval",
              "eval_regex",
              60,
              "Dynamic code matched eval regex policy",
              request,
              Map.of("function", String.valueOf(function), "code", abbreviate(code))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectLoadLibrary(
      String function, String path, boolean windows, RequestContext request) {
    if (!windows || path == null || path.isBlank()) {
      return Optional.empty();
    }
    if (path.startsWith("\\\\") || path.startsWith("//")) {
      return Optional.of(
          Detection.log(
              "loadLibrary",
              "loadLibrary_unc",
              60,
              "Native library load used a UNC path",
              request,
              Map.of("function", String.valueOf(function), "path", abbreviate(path))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectResponseDataLeak(
      String contentType, String content, RequestContext request) {
    if (contentType == null
        || content == null
        || !Pattern.compile("(?i)html|json|xml").matcher(contentType).find()) {
      return Optional.empty();
    }
    Optional<String> identityCard = firstValidIdentityCard(content);
    if (identityCard.isPresent()) {
      return dataLeak("Identity Card", identityCard.orElseThrow(), request);
    }
    Optional<String> mobileNumber = firstValidMobileNumber(content);
    if (mobileNumber.isPresent()) {
      return dataLeak("Mobile Number", mobileNumber.orElseThrow(), request);
    }
    Optional<String> bankCard = firstValidBankCard(content);
    if (bankCard.isPresent()) {
      return dataLeak("Bank Card", bankCard.orElseThrow(), request);
    }
    return Optional.empty();
  }

  public Optional<Detection> detectXssEcho(String content, RequestContext request) {
    if (content == null || content.isBlank()) {
      return Optional.empty();
    }
    for (String value : request.allParameterValues()) {
      if (value != null && !value.isBlank() && content.contains(value) && XSS_INPUT.matcher(value).find()) {
        return Optional.of(
            Detection.log(
                "response",
                "xss_echo",
                70,
                "Response echoes XSS-like request input",
                request,
                Map.of("value", abbreviate(value))));
      }
    }
    if (request.active() && XSS_INPUT.matcher(content).find()) {
      return Optional.of(
          Detection.log(
              "response",
              "xss_echo",
              60,
              "Response contains XSS-like content",
              request,
              Map.of("value", abbreviate(content))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellEval(
      String function, String code, RequestContext request) {
    String normalizedFunction = lower(function);
    if ((normalizedFunction.equals("eval") || normalizedFunction.equals("assert"))
        && request.hasParameterIn(code)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_eval",
              95,
              "Dynamic code execution is controlled by request input",
              request,
              Map.of("function", String.valueOf(function), "code", abbreviate(code))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellCommand(
      List<String> command, RequestContext request) {
    String joined = command == null ? "" : String.join(" ", command);
    if (!joined.isBlank() && request.hasParameterIn(joined)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_command",
              95,
              "Command execution is controlled by request input",
              request,
              Map.of("command", abbreviate(joined))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellFileWrite(
      String path, String content, RequestContext request) {
    String normalized = normalizePath(path);
    if (SCRIPT_FILE.matcher(normalized).matches()
        && (request.hasParameterIn(path) || request.hasParameterIn(content))) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_file_put_contents",
              95,
              "Request-controlled content is written to a server-side script",
              request,
              Map.of("path", normalized, "content", abbreviate(content))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellCallable(String function, RequestContext request) {
    String normalized = lower(function);
    if (WEBSHELL_CALLABLES.contains(normalized)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_callable",
              90,
              "Dangerous callable function selected",
              request,
              Map.of("function", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebshellLdPreload(
      String name, String value, RequestContext request) {
    String normalized = name == null ? "" : name.toUpperCase(Locale.ROOT);
    if (WEBSHELL_ENV.contains(normalized)) {
      return Optional.of(
          Detection.log(
              "webshell",
              "webshell_ld_preload",
              90,
              "Dangerous dynamic loader environment variable selected",
              request,
              Map.of("name", normalized, "value", abbreviate(value))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectXxeEntity(String name, String systemId, RequestContext request) {
    String value = systemId == null ? "" : systemId;
    if (value.startsWith("\\\\") || value.startsWith("//")) {
      return Optional.of(
          Detection.log(
              "xxe",
              "xxe_protocol",
              100,
              "XML external entity uses SMB/UNC path",
              request,
              Map.of("name", String.valueOf(name), "systemId", abbreviate(value))));
    }
    if (value.contains(":")) {
      String protocol = lower(value.substring(0, value.indexOf(':')));
      if (SSRF_PROTOCOLS.contains(protocol) || "http".equals(protocol) || "https".equals(protocol)) {
        return Optional.of(
            Detection.log(
                "xxe",
                "xxe_protocol",
                90,
                "XML external entity uses protocol " + protocol,
                request,
                Map.of("name", String.valueOf(name), "systemId", abbreviate(value))));
      }
    }
    return Optional.empty();
  }

  private static boolean isSqlExceptionSignal(
      String server, String code, String state, String message, String query) {
    return switch (server) {
      case "mysql" -> {
        if (code.equals("1062")) {
          yield query != null && Pattern.compile("(?i)rand").matcher(query).find();
        }
        if (code.equals("1064")) {
          yield Pattern.compile("(?i)syntax").matcher(message).find()
              && !Pattern.compile("(?i)in\\s*(\\(\\s*\\)|[^\\(\\w])").matcher(query).find();
        }
        yield Set.of("1060", "1105", "1367").contains(code);
      }
      case "pgsql" -> Set.of("42601", "22P02").contains(code) || Set.of("42601", "22P02").contains(state);
      case "sqlite" -> code.equals("1")
          && (message.contains("syntax") || message.contains("malformed match"));
      case "oracle" -> Set.of("933", "29257", "20000", "904", "19202", "1756", "1740", "920", "907", "911")
          .contains(code);
      case "hsql" -> Set.of("-5583", "-5584", "-5590").contains(code)
          || Set.of("42583", "42584", "42590").contains(state);
      case "mssql" -> Set.of("105", "245").contains(code);
      case "db2" -> state.equals("42603");
      default -> false;
    };
  }

  private static boolean hasUnbalancedQuotes(String value) {
    long single = value.chars().filter(ch -> ch == '\'').count();
    long doubleQuote = value.chars().filter(ch -> ch == '"').count();
    long backtick = value.chars().filter(ch -> ch == '`').count();
    return single % 2 != 0 || doubleQuote % 2 != 0 || backtick % 2 != 0;
  }

  private static boolean stackLooksReflective(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return false;
    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame);
      if (normalized.contains("java.lang.reflect")
          || normalized.contains("sun.reflect")
          || normalized.contains("jdk.internal.reflect")
          || normalized.contains("javax.script")
          || normalized.contains("ognl")
          || normalized.contains("templatesimpl")
          || normalized.contains("generatedmethodaccessor")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isInternalHost(String host) {
    if (host == null || host.isBlank()) {
      return false;
    }
    return host.equals("localhost")
        || host.equals("0")
        || host.equals("::1")
        || host.startsWith("127.")
        || host.startsWith("10.")
        || host.startsWith("192.168.")
        || host.startsWith("169.254.")
        || host.matches("172\\.(1[6-9]|2\\d|3[0-1])\\..*");
  }

  private static boolean looksObfuscatedHost(String host) {
    if (host == null || host.isBlank()) {
      return false;
    }
    return host.startsWith("0x")
        || host.matches("\\d+")
        || host.matches(".*%[0-9a-fA-F]{2}.*")
        || host.matches(".*[。｡．].*");
  }

  private static boolean isLocalClasspathResource(String rawUrl, String scheme, String path) {
    if ("jar".equals(scheme) && rawUrl.startsWith("jar:file:")) {
      return true;
    }
    return "file".equals(scheme)
        && path.startsWith("/usr/local/tomcat/lib/")
        && path.endsWith(".jar");
  }

  private static String normalizePath(String path) {
    if (path == null) {
      return "";
    }
    try {
      return Path.of(path).normalize().toString().replace('\\', '/').toLowerCase(Locale.ROOT);
    } catch (RuntimeException e) {
      return path.replace('\\', '/').toLowerCase(Locale.ROOT);
    }
  }

  private static String protocolOf(String value) {
    if (value == null) {
      return "";
    }
    int index = value.indexOf("://");
    if (index < 1) {
      return "";
    }
    return value.substring(0, index).toLowerCase(Locale.ROOT);
  }

  private static String lower(String value) {
    return value == null ? "" : value.toLowerCase(Locale.ROOT);
  }

  private static Optional<Detection> dataLeak(
      String kind, String matchedValue, RequestContext request) {
    return Optional.of(
        Detection.log(
            "response",
            "response_dataLeak",
            80,
            "PII leak detected: " + kind,
            request,
            Map.of("kind", kind, "match", matchedValue)));
  }

  private static Optional<String> firstValidIdentityCard(String content) {
    var matcher = CHINA_ID.matcher(content);
    int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    while (matcher.find()) {
      String id = matcher.group();
      if (id.charAt(0) == '0') {
        continue;
      }
      int sum = 0;
      for (int i = 0; i < weights.length; i++) {
        sum += Character.digit(id.charAt(i), 10) * weights[i];
      }
      char check = id.charAt(17);
      sum += (check == 'X' || check == 'x') ? 10 : Character.digit(check, 10);
      if (sum % 11 == 1) {
        return Optional.of(id);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidMobileNumber(String content) {
    var matcher = CHINA_MOBILE.matcher(content);
    while (matcher.find()) {
      if (CHINA_MOBILE_PREFIXES.contains(matcher.group(1))) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstValidBankCard(String content) {
    var matcher = BANK_CARD.matcher(content);
    while (matcher.find()) {
      String card = matcher.group().replace(" ", "").replace("-", "");
      if (luhn(card)) {
        return Optional.of(matcher.group());
      }
    }
    return Optional.empty();
  }

  private static boolean luhn(String digits) {
    int sum = 0;
    boolean doubleDigit = false;
    for (int i = digits.length() - 1; i >= 0; i--) {
      int value = Character.digit(digits.charAt(i), 10);
      if (value < 0) {
        return false;
      }
      if (doubleDigit) {
        value *= 2;
      }
      sum += value / 10 + value % 10;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 == 0;
  }

  public static String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    if (value.length() <= 300) {
      return value;
    }
    return value.substring(0, 300) + "...";
  }

  public static List<String> commandFromObject(Object command) {
    if (command instanceof List<?> list) {
      var values = new ArrayList<String>();
      for (Object item : list) {
        values.add(String.valueOf(item));
      }
      return values;
    }
    return List.of(String.valueOf(command));
  }
}
