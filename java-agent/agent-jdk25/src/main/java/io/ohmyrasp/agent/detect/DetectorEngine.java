package io.ohmyrasp.agent.detect;

import io.ohmyrasp.agent.model.Detection;
import io.ohmyrasp.agent.model.RequestContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class DetectorEngine {
  private static final Pattern SQLI_USER_INPUT =
      Pattern.compile(
          "(?is)(?:'\\s*(?:or|and)\\s+(?:\\d+\\s*=\\s*\\d+|'[^']*'\\s*=\\s*'[^']*')|union\\s+select|--|/\\*|;\\s*(?:select|insert|update|delete|drop|alter)\\b)");
  private static final Pattern SQL_POLICY =
      Pattern.compile(
          "(?is)(?:\\bunion\\s+(?:all\\s+)?select\\b|\\binformation_schema\\b|\\binto\\s+(?:out|dump)file\\b|/\\*!|\\bload_file\\s*\\(|\\bsleep\\s*\\(|\\bbenchmark\\s*\\()");
  private static final Pattern H2_CODE_CONTAINER =
      Pattern.compile("(?is)\\bcreate\\s+(?:alias|trigger)\\b");
  private static final Pattern H2_CODE_PRIMITIVE =
      Pattern.compile(
          "(?is)(?:java\\.lang\\.runtime|runtime\\s*\\.\\s*getruntime\\s*\\(|processbuilder|scriptenginemanager|javax\\.naming\\.initialcontext|urlclassloader|//\\s*javascript)");
  private static final Pattern H2_REMOTE_RUNSCRIPT =
      Pattern.compile("(?is)\\brunscript\\s+from\\s+['\"]?\\s*(?:https?|ftp|jar|ldap|rmi)://");
  private static final Pattern H2_INIT_SETTING = Pattern.compile("(?is)(?:^|;)\\s*init\\s*=");
  private static final Pattern BASE64_CONFIG_VALUE =
      Pattern.compile("(?is)^[A-Za-z0-9+/=_-]{32,8192}$");
  private static final Pattern DERBY_CODE_LOADING =
      Pattern.compile(
          "(?is)(?:\\bsqlj\\s*\\.\\s*(?:install|replace)_jar\\s*\\(|\\bsyscs_util\\s*\\.\\s*syscs_set_database_property\\s*\\(\\s*['\"]derby\\.database\\.classpath['\"]|\\blanguage\\s+java\\b.{0,240}\\bexternal\\s+name\\b|\\bparameter\\s+style\\s+java\\b.{0,240}\\bexternal\\s+name\\b)");
  private static final Pattern MYSQL_JDBC_AUTO_DESERIALIZE =
      Pattern.compile("(?is)(?:[?&;]|^)\\s*autodeserialize\\s*=\\s*(?:true|1|yes)\\b");
  private static final Pattern MYSQL_JDBC_DESERIALIZATION_TRIGGER =
      Pattern.compile(
          "(?is)(?:[?&;]\\s*(?:statementinterceptors|queryinterceptors)\\s*=|serverstatusdiffinterceptor|[?&;]\\s*detectcustomcollations\\s*=\\s*(?:true|1|yes)\\b)");
  private static final Pattern SCRIPT_LITERAL_EXECUTE =
      Pattern.compile("(?is)['\"][^'\"]{1,120}['\"]\\s*\\.\\s*execute\\s*\\(");
  private static final Pattern SCRIPT_COMMAND_VARIABLE_EXECUTE =
      Pattern.compile(
          "(?is)\\b(?:cmd|command)\\s*=\\s*['\"][^'\"]{1,120}['\"].{0,240}\\b(?:cmd|command)\\s*\\.\\s*execute\\s*\\(");
  private static final Pattern JAVA_UNICODE_ESCAPE =
      Pattern.compile("\\\\u+([0-9a-fA-F]{4})");
  private static final Pattern COMMAND_COMMON =
      Pattern.compile(
          "(?is)(?:cat\\s+/etc/passwd|nc\\b.{0,40}\\s-e\\s+/bin/(?:ba)?sh|bash\\s+-i\\b|/dev/tcp/|curl\\b.{0,80}\\|\\s*(?:sh|bash)|wget\\b.{0,80}\\|\\s*(?:sh|bash)|\\{echo,.{10,400}\\}\\|\\{base64,-d\\})");
  private static final Pattern COMMAND_META = Pattern.compile("[;&|`$<>]|\\$\\{?IFS\\}?");
  private static final Pattern COMMAND_SENSITIVE_AFTER_JOIN =
      Pattern.compile("(?is)(?:;|&&|\\|\\|?|`)\\s*(?:cat|bash|sh|nc|curl|wget|python|perl|php)\\b");
  private static final Pattern COMMAND_DNSLOG =
      Pattern.compile("(?is)(^|\\W)(curl|ping|wget|nslookup|dig)\\W.*");
  private static final Pattern GENERATED_SCRIPT_EXTENSION =
      Pattern.compile("(?is).+\\.(?:gnuplot|gp|plt|plot|cmd|sh|bash|ps1)$");
  private static final Pattern GENERATED_SCRIPT_EXEC_PRIMITIVE =
      Pattern.compile("(?is)(?:^|[^\\w])(?:system\\s*(?:\\(|[\"'])|exec\\s*\\(|shell\\s*\\(|`[^`]{1,240}`)");
  private static final Pattern DANGEROUS_FILE_READ =
      Pattern.compile(
          "(?is)(?:^|/)(?:etc/(?:issue|passwd|shadow|apache2/apache2\\.conf)|proc/self/environ|root/\\.ssh|root/\\.bash_(?:history|profile)|\\.bash_history|\\.zsh_history|\\.mysql_history|id_rsa|windows/system32/(?:inetsrv/metabase\\.xml|drivers/etc/hosts))$");
  private static final Pattern SCRIPT_FILE =
      Pattern.compile("(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)\\.?$");
  private static final Pattern SCRIPT_FILE_REQUEST_PATH =
      Pattern.compile(
          "(?is).+\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)(?:[;/\\\\].*|\\.*$)");
  private static final Pattern SCRIPT_FILE_TOKEN =
      Pattern.compile("(?is)(?:[a-z]:)?(?:[./][^\\s\"'<>;,)]*)?[^\\s\"'<>;,)]*\\.(?:aspx?|jspx?|php[345]?|phar|phtml|sh|py|pl|rb|so|dll|dylib|ashx|cer|asa)\\.?");
  private static final Pattern CLEAN_FILE =
      Pattern.compile("(?is).+\\.(?:jpg|jpeg|png|gif|bmp|txt|rar|zip)$");
  private static final Pattern HTML_FILE = Pattern.compile("(?is).+\\.(?:htm|html|js)$");
  private static final Pattern EXECUTABLE_FILE =
      Pattern.compile("(?is).+\\.(?:exe|dll|scr|vbs|cmd|bat)$");
  private static final Pattern JAVA_ARCHIVE_FILE =
      Pattern.compile("(?is).+\\.(?:jar|war|ear|class)\\.?$");
  private static final Pattern NTFS_STREAM = Pattern.compile("(?is).*::\\$(?:data|index)$");
  private static final Pattern WINDOWS_ABSOLUTE_PATH = Pattern.compile("(?i)^[a-z]:/.*");
  private static final Pattern READ_SAFE_EXTENSION =
      Pattern.compile(
          "(?is).+\\.(?:docx?|dotx?|docm|dotm|xlsx?|xltx?|xlsm|xlsb|pptx?|ppsx?|ppsm|potx?|potm|7z|tar|gz|bz2|xz|rar|zip|jpe?g|png|gif|bmp|txt)$");
  private static final Pattern DNSLOG_DOMAIN =
      Pattern.compile(
          "(?i).*((?:ceye|exeye|sslip|nip)\\.io|dnslog\\.cn|(?:vcap|bxss)\\.me|xip\\.(?:name|io)|burpcollaborator\\.net|tu4\\.org|2xss\\.cc|request\\.bin|requestbin\\.net|pipedream\\.net|canarytokens\\.com)$");
  private static final Pattern DNSLOG_TEXT =
      Pattern.compile(
          "(?i).*((?:ceye|exeye|sslip|nip)\\.io|dnslog\\.cn|(?:vcap|bxss)\\.me|xip\\.(?:name|io)|burpcollaborator\\.net|tu4\\.org|2xss\\.cc|request\\.bin|requestbin\\.net|pipedream\\.net|canarytokens\\.com)(?:[/:?].*)?");
  private static final Pattern JAAS_JNDI_LOGIN_MODULE =
      Pattern.compile("(?is)\\bcom\\.sun\\.security\\.auth\\.module\\.JndiLoginModule\\b");
  private static final Pattern JAAS_REMOTE_PROVIDER_URL =
      Pattern.compile(
          "(?is)\\b(?:(?:java\\.naming\\.)?provider\\.url|(?:user|group)\\.provider\\.url)\\s*=\\s*[\"']?\\s*((?:ldap|ldaps|rmi|iiop|corbaname|corbaloc)://[^\\s\"';]+)");
  private static final Pattern REQUEST_JNDI_LOOKUP =
      Pattern.compile("(?is)\\$\\{[^\\r\\n]{0,512}?jndi\\s*:\\s*([a-z][a-z0-9.+-]{0,20})://");
  private static final Pattern REQUEST_XXE_EXTERNAL_ENTITY =
      Pattern.compile(
          "(?is)<!\\s*DOCTYPE\\b.{0,4096}<!\\s*ENTITY\\b.{0,1024}\\b(?:SYSTEM|PUBLIC)\\b.{0,512}['\"]\\s*([a-z][a-z0-9.+-]{0,20}):");
  private static final Pattern REQUEST_TYPED_PARAMETER_CLASS =
      Pattern.compile(
          "^(?:\\[+L?)?[A-Za-z_$][\\w$]*(?:[.$][A-Za-z_$][\\w$]*){1,}(?:;|\\[\\])?$");
  private static final Pattern TYPED_PAYLOAD_CLASS_ATTRIBUTE =
      Pattern.compile(
          "(?is)\\b(?:type|class|classname|className|javaClass|@type)\\s*=\\s*['\"]([^'\"]{1,512})['\"]");
  private static final Pattern TYPED_PAYLOAD_JSON_TYPE =
      Pattern.compile(
          "(?is)[\"'](?:@type|class|classname|className|javaClass)[\"']\\s*:\\s*[\"']([^\"']{1,512})[\"']");
  private static final Pattern TYPED_PAYLOAD_YAML_TAG =
      Pattern.compile("(?m)!{1,2}\\s*([A-Za-z_$][\\w$]*(?:[./$][A-Za-z_$][\\w$]*){1,80})");
  private static final Pattern TYPED_PAYLOAD_REMOTE_NAMING_URL =
      Pattern.compile("(?is)\\b(ldap|ldaps|rmi|iiop|corba|corbaname|corbaloc)://[^\\s\"'<>]+");
  private static final Pattern XML_PAYLOAD_CLASS_ATTRIBUTE =
      Pattern.compile(
          "(?is)\\b(?:class|type|classname|className|javaClass)\\s*=\\s*['\"]([^'\"<>]{1,512})['\"]");
  private static final Pattern XML_PAYLOAD_CLASS_ELEMENT =
      Pattern.compile(
          "(?is)<\\s*(?:[A-Za-z0-9_.-]+:)?(?:class|type|classname|className|javaClass)\\b[^>]*>"
              + "\\s*([^<\\s]{1,512})\\s*</\\s*(?:[A-Za-z0-9_.-]+:)?"
              + "(?:class|type|classname|className|javaClass)\\s*>");
  private static final Pattern XML_PAYLOAD_JAVA_TYPE_TAG =
      Pattern.compile("(?is)<\\s*/?\\s*([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*){1,80})\\b");
  private static final Pattern SENSITIVE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|ops|manage|management|console)(?:/|$)");
  private static final Pattern INTERNAL_FORWARD_JSP_SUFFIX =
      Pattern.compile("(?i);\\s*\\.jspx?(?:$|[/?#])");
  private static final Pattern INTERNAL_FORWARD_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:auth|admin|user|users|role|roles|permission|permissions|token|tokens|debug|config|ops|manage|management|console)(?:/|$)");
  private static final Pattern PROTECTED_WEBAPP_RESOURCE =
      Pattern.compile("(?i)(?:^|[/?&=])((?:web-inf|meta-inf))(?:[/\\\\?&#=]|$)");
  private static final Pattern JWT_HMAC_ALGORITHM =
      Pattern.compile("\"alg\"\\s*:\\s*\"(HS(?:256|384|512))\"");
  private static final Pattern COMPACT_JWT =
      Pattern.compile("(?is)^[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{6,}$");
  private static final Pattern JWT_VERIFICATION_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:api|de2api|auth|token|tokens|admin|console|manage|management|user|users|datasource|dashboard|system|settings)(?:[;/]|/|$)");
  private static final Pattern EMPTY_CREDENTIAL_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:webtools|control|admin|admins|console|manage|management|account|accounts|user|users)(?:[;/]|/|$)");
  private static final Pattern DEFAULT_CREDENTIAL_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|console|manager|host-manager|manage|management|api|jolokia|login|cas|oauth|securityrealm|webtools|accounting)(?:[;/]|/|$)");
  private static final Pattern SCHEDULER_JOB_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:run|execute|trigger|executor|executors|job|jobs|scheduler|schedule|task|tasks)(?:[;/]|/|$)");
  private static final Pattern DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:actuator/gateway(?:/routes)?|api/setup/validate|setup/validate|h2-console/login\\.do|datasource/validate|connection/validate|context\\.json|dataimport|sampler|verification|checkscript|programexport|gremlin|console|_search|_scripts|config|configs|settings)(?:[;/]|/|$)");
  private static final Pattern SETUP_STATE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:server-info\\.action|setup|install|bootstrap|setupadministrator\\.action|finishsetup\\.action)(?:[;/]|/|$)");
  private static final Pattern TEMPLATE_PARAMETER_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:select|query|queryfield|queryfieldbysql|search|render|report|template|templates|velocity|view|views)(?:[;/]|/|$)");
  private static final Pattern TEMPLATE_LOADER_ENABLE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|config|configs|settings|schema|template|templates|velocity)(?:[;/]|/|$)");
  private static final Pattern TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:contactadministrators|contact|support|feedback|message|messages|mail|email)(?:[!.;/]|/|$)");
  private static final Pattern TEMPLATE_SOURCE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|administrator|adminapi|ajax|cfc|control|filemanager|include|includes|macro|preview|render|resource|resources|template|templates|tinymce|view|views)(?:[!;/]|/|$)");
  private static final Pattern TEMPLATE_SOURCE_SENSITIVE_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:web\\.xml|server\\.xml|context\\.xml|confluence\\.cfg\\.xml|database\\.properties|application\\.properties|password\\.properties|proc/self/environ|passwd|shadow|[^/]*(?:access|application|coldfusion-out|error|server)\\.log)(?:$|[?#])");
  private static final Pattern EXPRESSION_BODY_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:service/(?:rest|extdirect)|repository|repositories|groups?|roles?|users?|admin|manage|management|config|settings)(?:[;/]|/|$)");
  private static final Pattern OGC_XPATH_CONTROL_PATH =
      Pattern.compile("(?i)(?:^|/)(?:ows|wfs|wms|wps)(?:[;/]|/|$)");
  private static final Pattern OGC_XPATH_XML_TEXT_FIELD =
      Pattern.compile(
          "(?is)<\\s*(?:[A-Za-z0-9_.-]+:)?(valueReference|propertyName)\\b[^>]*>"
              + "(.*?)"
              + "<\\s*/\\s*(?:[A-Za-z0-9_.-]+:)?\\1\\s*>");
  private static final Pattern OGC_FILTER_SQL_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:--|/\\*|\\bunion\\s+(?:all\\s+)?select\\b|\\bcast\\s*\\(\\s*\\(?\\s*\\(?\\s*select\\b|\\bselect\\b.{0,160}\\b(?:version|current_database|database|user)\\s*\\(|\\b(?:pg_sleep|sleep|benchmark)\\s*\\()");
  private static final Pattern OGNL_DELEGATED_PARAMETER_DOT =
      Pattern.compile(
          "(?is)\\.\\s*findValue\\s*\\(\\s*#parameters\\.([A-Za-z0-9_.-]{1,80})\\b");
  private static final Pattern OGNL_DELEGATED_PARAMETER_BRACKET =
      Pattern.compile(
          "(?is)\\.\\s*findValue\\s*\\(\\s*#parameters\\s*\\[\\s*['\"]([A-Za-z0-9_.-]{1,80})['\"]\\s*\\]");
  private static final Pattern REMOTE_CONTENT_STREAM_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|config|configs|settings|debug|dump|select|stream|streams|content)(?:[;/]|/|$)");
  private static final Pattern REMOTE_CONTENT_STREAM_ENABLE =
      Pattern.compile(
          "(?is)(?:request\\s*dispatcher\\s*\\.\\s*request\\s*parsers\\s*\\.\\s*enable\\s*remote\\s*streaming|requestdispatcher\\.requestparsers\\.enableremotestreaming|enable\\s*remote\\s*streaming|enableremotestreaming|remote[_-]?streaming)\\s*[\"']?\\s*[:=]\\s*(?:true|1|yes)\\b");
  private static final Pattern TEMPLATE_PARAMETER_LOADER_ENABLE =
      Pattern.compile(
          "(?is)[\"']?\\s*((?:params?|parameters?|request)\\s*[._-]?\\s*resource\\s*[._-]?\\s*loader\\s*[._-]?\\s*enabled)\\s*[\"']?\\s*[:=]\\s*[\"']?\\s*(?:true|1|yes|on)\\b");
  private static final Pattern REMOTE_IMPORT_SCRIPT_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:admin|control|dataimport|datafile|import|imports|load|loads|manage|management|upload|viewdatafile|webtools)(?:[;/]|/|$)");
  private static final Pattern REPOSITORY_WEBROOT_WRITE_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:_snapshot|snapshot|snapshots|backup|backups|repository|repositories|repo)(?:[;/]|/|$)");
  private static final Pattern MESSAGE_SELECTOR_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:websocket|sockjs|stomp|message|messages|topic|queue|gs-guide-websocket)(?:[;/]|/|$)");
  private static final Pattern STOMP_COMMAND =
      Pattern.compile("(?im)(?:^|[\\r\\n])(?:CONNECT|SUBSCRIBE|SEND|MESSAGE|UNSUBSCRIBE)\\b");
  private static final Pattern STOMP_SELECTOR_HEADER =
      Pattern.compile("(?im)(?:^|[\\r\\n])selector\\s*:\\s*([^\\r\\n\\u0000]{1,1000})");
  private static final Pattern PLOT_COMMAND_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:q|graph|graphs|plot|plots|chart|charts|render|query)(?:[;/]|/|$)");
  private static final Pattern SQL_SORT_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:api|case|cases|list|lists|page|pages|query|search|table|track)(?:[;/]|/|$)");
  private static final Pattern SQL_SORT_CONTEXT_BODY =
      Pattern.compile("(?is)\"(?:orders?|sort(?:ers?)?|pageable|pagination)\"\\s*:");
  private static final Pattern SQL_SORT_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:^|[,;])\\s*(?:if\\s*\\(|case\\s+when|select\\b|sleep\\s*\\(|benchmark\\s*\\(|extractvalue\\s*\\(|updatexml\\s*\\(|load_file\\s*\\()|(?:--|#|/\\*)");
  private static final Pattern SQL_IDENTIFIER_CONTROL_PATH =
      Pattern.compile(
          "(?i)(?:^|/)(?:graphql|api|query|queries|metrics?|logs?|trace|traces|search|table|tables)(?:[;/]|/|$)");
  private static final Pattern SQL_IDENTIFIER_CONTEXT_BODY =
      Pattern.compile(
          "(?is)\"(?:query|variables|condition|metricname|tablename|columnname|fieldname|metric|table|column|dimension)\"\\s*:");
  private static final Pattern SAFE_SQL_IDENTIFIER_VALUE =
      Pattern.compile("(?is)^[A-Za-z0-9_.$:-]{1,128}$");
  private static final Pattern SQL_IDENTIFIER_INJECTION_VALUE =
      Pattern.compile(
          "(?is)(?:\\b(?:where|union|select|join|sleep|benchmark|case\\s+when)\\b|\\binformation_schema\\b|(?:--|#|/\\*|;))");
  private static final Pattern REMOTE_JOB_ARTIFACT =
      Pattern.compile(
          "(?is)[\"'](?:appresource|spark\\.jars|sparkjars|jobjar|appjar|jarurl|resource)[\"']\\s*[:=]\\s*[\"']((?:https?|ftp)://[^\"'\\s,]+\\.(?:jar|war|ear)(?:[?#][^\"'\\s,]*)?)[\"']");
  private static final Pattern REMOTE_JOB_MAIN_CLASS =
      Pattern.compile(
          "(?is)[\"'](?:mainclass|main_class|entryclass|class)[\"']\\s*[:=]\\s*[\"'][A-Za-z_$][\\w.$]{0,180}[\"']");
  private static final Pattern REMOTE_JOB_COMMAND_VALUE =
      Pattern.compile(
          "(?is)[\"'](?:command|cmd|gluesource|shell)[\"']\\s*[:=]\\s*[\"']([^\"']{1,800})[\"']");
  private static final Pattern REMOTE_JOB_SHELL_COMMAND =
      Pattern.compile("(?is)(?:^|\\W)(?:bash|sh|cmd|powershell|pwsh|nc|curl|wget)\\b");
  private static final Pattern JAVA_CONFIG_CONSTRUCTOR_ARGUMENT =
      Pattern.compile("(?s)[\"']([^\"']{1,2048})[\"']");
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
  private static final Set<String> REMOTE_CLASSLOADER_PROTOCOLS =
      Set.of("http", "https", "ftp", "ldap", "rmi");
  private static final Set<String> REMOTE_CONFIG_PROTOCOLS =
      Set.of("http", "https", "ftp", "ldap", "rmi");
  private static final Set<String> JNDI_LOOKUP_PROTOCOLS =
      Set.of("ldap", "ldaps", "rmi", "dns", "iiop", "corba", "corbaname", "corbaloc", "nis");
  private static final Set<String> JNDI_DRIVER_PARAMETER_NAMES =
      Set.of("driver", "driverclass", "driverclassname", "jdbcdriver", "jdbcdriverclass");
  private static final Set<String> JNDI_REMOTE_URL_PARAMETER_NAMES =
      Set.of(
          "url",
          "jdbcurl",
          "jndiurl",
          "providerurl",
          "javanamingproviderurl",
          "connectionurl",
          "datasourceurl");
  private static final Set<String> XXE_EXTERNAL_ENTITY_PROTOCOLS =
      Set.of("file", "jar", "http", "https", "ftp", "gopher", "ldap", "rmi", "netdoc");
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
  private static final Set<String> JAVA_ARCHIVE_UPLOAD_TERMS =
      Set.of(
          "plugin",
          "plugins",
          "extension",
          "extensions",
          "addon",
          "addons",
          "module",
          "modules",
          "connector",
          "connectors",
          "driver",
          "drivers",
          "jar",
          "jars",
          "job",
          "jobs",
          "udf",
          "udfs",
          "app",
          "apps",
          "application",
          "applications");
  private static final Set<String> JAVA_ARCHIVE_UPLOAD_ACTIONS =
      Set.of("upload", "add", "install", "deploy", "load", "import", "submit", "create");
  private static final Set<String> JAVA_ARCHIVE_UPLOAD_PARAMETERS =
      Set.of(
          "plugin",
          "pluginfile",
          "extension",
          "extensionfile",
          "jar",
          "jarfile",
          "jobjar",
          "driver",
          "driverjar",
          "connector",
          "module");
  private static final Set<String> REMOTE_JOB_MECHANISMS =
      Set.of("spark", "sparkrest", "yarn", "hadoop", "flink", "job", "jobscheduler");
  private static final Set<String> REMOTE_JOB_PATH_TERMS =
      Set.of(
          "job",
          "jobs",
          "app",
          "apps",
          "application",
          "applications",
          "submission",
          "submissions",
          "driver",
          "drivers",
          "cluster",
          "batch",
          "batches");
  private static final Set<String> REMOTE_JOB_PATH_ACTIONS =
      Set.of("create", "submit", "submissions", "run", "execute", "apps", "batches");
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
  private static final Set<String> INTERNAL_SERVICE_USER_AGENTS =
      Set.of("nacos-server");
  private static final Set<String> INTERNAL_FORWARD_PARAMETERS =
      Set.of(
          "jsp", "view", "viewname", "forward", "forwardto", "dispatch", "dispatcher", "template");
  private static final Set<String> EMPTY_CREDENTIAL_USERNAME_PARAMETERS =
      Set.of("username", "user", "userid", "login", "loginid", "account");
  private static final Set<String> EMPTY_CREDENTIAL_PASSWORD_PARAMETERS =
      Set.of("password", "passwd", "pwd", "pass");
  private static final Set<String> EMPTY_CREDENTIAL_BYPASS_PARAMETERS =
      Set.of(
          "requirepasswordchange",
          "passwordchange",
          "changepassword",
          "forcepasswordchange",
          "externalloginkey",
          "securitygroupid");
  private static final Set<String> DEFAULT_CREDENTIAL_USERNAME_PARAMETERS =
      Set.of("username", "user", "userid", "login", "loginid", "account", "jusername");
  private static final Set<String> DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS =
      Set.of("password", "passwd", "pwd", "pass", "jpassword");
  private static final Set<String> SCHEDULER_JOB_TYPE_PARAMETERS =
      Set.of("gluetype", "scripttype", "jobtype", "commandtype", "tasktype", "executortype");
  private static final Set<String> SCHEDULER_JOB_SOURCE_PARAMETERS =
      Set.of(
          "gluesource",
          "script",
          "source",
          "command",
          "commandline",
          "shell",
          "code",
          "payload");
  private static final Set<String> SCHEDULER_JOB_CONTEXT_PARAMETERS =
      Set.of(
          "jobid",
          "logid",
          "logdatetime",
          "executorhandler",
          "executorparams",
          "executorblockstrategy",
          "broadcastindex",
          "broadcasttotal",
          "glueupdatetime",
          "gluetype",
          "gluesource");
  private static final Set<String> DEBUG_PROCESS_LAUNCH_PARAMETERS =
      Set.of("exepath", "executable", "executablepath", "command", "commandline", "cmd");
  private static final Set<String> DYNAMIC_SCRIPT_CONFIG_PARAMETERS =
      Set.of(
          "dataconfig",
          "routeconfig",
          "routedefinition",
          "gatewayroute",
          "filterconfig",
          "scriptfields",
          "scriptfield",
          "scriptconfig",
          "validationrules",
          "groovyprogram");
  private static final Set<String> EXPRESSION_HEADER_NAMES =
      Set.of(
          "springcloudfunctionroutingexpression",
          "spring.cloud.function.routingexpression",
          "routingexpression",
          "expression",
          "spel",
          "script");
  private static final Set<String> EXPRESSION_PARSER_HEADER_NAMES =
      Set.of("contenttype", "contentdisposition");
  private static final Set<String> REQUEST_EXPRESSION_PARAMETER_NAMES =
      Set.of(
          "expression",
          "expr",
          "spel",
          "ognl",
          "routingexpression",
          "script",
          "valueexpression",
          "querystring",
          "responsetype");
  private static final Set<String> OGC_XPATH_EXPRESSION_PARAMETERS =
      Set.of("valuereference", "propertyname");
  private static final Set<String> OGC_FILTER_SQL_PARAMETERS =
      Set.of("cqlfilter", "ecqlfilter", "filter");
  private static final Set<String> OGC_XPATH_SERVICES = Set.of("wfs", "wms", "wps", "ows");
  private static final Set<String> OGC_XPATH_REQUESTS =
      Set.of(
          "getpropertyvalue",
          "getfeature",
          "getmap",
          "getfeatureinfo",
          "getlegendgraphic",
          "execute");
  private static final Set<String> TEMPLATE_PARAMETER_NAMES =
      Set.of(
          "template",
          "templatebody",
          "templatecontent",
          "templatesource",
          "templatepayload",
          "templatecustom",
          "v.template.custom",
          "vtemplatecustom",
          "velocitytemplate",
          "freemarkertemplate",
          "ftltemplate",
          "thymeleaftemplate");
  private static final Set<String> TEMPLATE_ENGINE_PARAMETER_NAMES =
      Set.of("wt", "engine", "renderer", "renderengine", "templateengine", "viewengine");
  private static final Set<String> TEMPLATE_ENGINE_VALUES =
      Set.of("velocity", "freemarker", "ftl", "thymeleaf", "mustache", "pebble", "template");
  private static final Set<String> TEMPLATE_MESSAGE_PARAMETER_NAMES =
      Set.of("body", "comment", "content", "description", "details", "message", "subject", "text");
  private static final Set<String> TEMPLATE_SOURCE_PARAMETER_NAMES =
      Set.of(
          "class",
          "classname",
          "bundle",
          "bundlefile",
          "bundlepath",
          "javaclass",
          "locale",
          "localefile",
          "localepath",
          "messagebundle",
          "messagebundlepath",
          "resource",
          "resourcefile",
          "resourcepath",
          "resourceurl",
          "template",
          "templatepath",
          "templatefile",
          "templateurl",
          "templatesource",
          "templatesourceurl",
          "templatesourcepath");
  private static final Set<String> REMOTE_CONTENT_STREAM_URL_PARAMETERS =
      Set.of(
          "stream.url",
          "streamurl",
          "streamsource",
          "streamsourceurl",
          "contentstreamurl",
          "content.stream.url",
          "resource.stream.url");
  private static final Set<String> REMOTE_CONTENT_STREAM_CONFIG_PARAMETERS =
      Set.of("config", "body", "payload", "json", "data", "settings", "setproperty", "property");
  private static final Set<String> REMOTE_IMPORT_SOURCE_PARAMETERS =
      Set.of(
          "datafilelocation",
          "definitionlocation",
          "schemalocation",
          "templateurl",
          "templateuri",
          "template",
          "sourceurl",
          "sourceuri",
          "remoteurl",
          "dataurl",
          "fileurl",
          "url");
  private static final Set<String> REMOTE_IMPORT_TARGET_PARAMETERS =
      Set.of(
          "datafilesave",
          "savepath",
          "savefile",
          "targetpath",
          "targetfile",
          "outputpath",
          "outputfile",
          "destination",
          "dest",
          "path");
  private static final Set<String> REMOTE_IMPORT_URL_FLAG_PARAMETERS =
      Set.of("datafileisurl", "definitionisurl", "isurl", "remote", "fromurl", "urlinput");
  private static final Set<String> PLOT_COMMAND_PARAMETERS =
      Set.of("yrange", "y2range", "xrange", "x2range", "key");
  private static final Set<String> PLOT_CONTEXT_PARAMETERS =
      Set.of(
          "m",
          "start",
          "end",
          "wxh",
          "style",
          "grid",
          "json",
          "yrange",
          "y2range",
          "xrange",
          "x2range",
          "key");
  private static final Set<String> SQL_SORT_INJECTION_FIELD_NAMES =
      Set.of(
          "direction",
          "dir",
          "order",
          "orderby",
          "ordertype",
          "sort",
          "sortby",
          "sortdirection",
          "sortorder",
          "sorttype",
          "type");
  private static final Set<String> SQL_IDENTIFIER_INJECTION_FIELD_NAMES =
      Set.of(
          "column",
          "columnname",
          "dimension",
          "dimensionname",
          "entity",
          "entityname",
          "field",
          "fieldname",
          "metric",
          "metricname",
          "table",
          "tablename");
  private static final Map<String, String> DEFAULT_JWT_HMAC_SECRETS =
      Map.of("hugegraph-default-token-secret", "FXQXbJtbCLxODc6tGci732pkH1cyf8Qg");
  private static final Set<String> DEFAULT_ENCRYPTED_COOKIE_NAMES = Set.of("rememberme");
  private static final Set<String> CLIENT_STATE_PARAMETER_NAMES =
      Set.of(
          "javax.faces.viewstate",
          "jakarta.faces.viewstate",
          "viewstate",
          "facesviewstate",
          "clientstate");
  private static final Map<String, String> DEFAULT_COOKIE_AES_KEYS =
      Map.of("shiro-default-aes-key", "kPH+bIxk5D2deZiIxcaaaA==");
  private static final Map<String, String> DEFAULT_CREDENTIAL_PAIRS =
      Map.ofEntries(
          Map.entry("admin\nadmin", "activemq-admin-default"),
          Map.entry("tomcat\ntomcat", "tomcat-manager-default"),
          Map.entry("weblogic\noracle@123", "weblogic-lab-default"),
          Map.entry("weblogic\nweblogic", "weblogic-common-default"),
          Map.entry("admin\nvulhub", "jenkins-lab-default"));
  private static final Set<String> DESERIALIZATION_BLACKLIST =
      Set.of(
          "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
          "org.apache.xalan.xsltc.trax.TemplatesImpl",
          "com.sun.rowset.JdbcRowSetImpl",
          "java.lang.Runtime",
          "java.lang.ProcessBuilder",
          "java.lang.ClassLoader",
          "java.net.URLClassLoader",
          "javax.script.ScriptEngineManager",
          "javax.naming.InitialContext",
          "javax.naming.ldap.Rdn$RdnEntry",
          "javax.sql.rowset.BaseRowSet",
          "sun.rmi.registry.RegistryImpl_Stub",
          "org.mozilla.javascript.NativeJavaObject",
          "org.mozilla.javascript.NativeJavaArray",
          "org.mozilla.javascript.ScriptableObject",
          "org.mozilla.javascript.tools.shell.Environment",
          "org.springframework.context.support.FileSystemXmlApplicationContext",
          "org.springframework.context.support.ClassPathXmlApplicationContext",
          "org.apache.commons.collections.functors.InvokerTransformer",
          "org.apache.commons.collections4.functors.InvokerTransformer",
          "org.codehaus.groovy.runtime.ConvertedClosure",
          "org.springframework.beans.factory.ObjectFactory",
          "javax.management.BadAttributeValueExpException",
          "io.ohmyrasp.playground.EvilSerialized");
  private static final Set<String> PROTOCOL_CONFIG_INSTANTIATION_TYPES =
      Set.of(
          "org.springframework.context.support.FileSystemXmlApplicationContext",
          "org.springframework.context.support.ClassPathXmlApplicationContext",
          "org.apache.xbean.spring.context.ResourceXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
          "com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext");
  private static final Set<String> DESERIALIZATION_GADGET_PREFIXES =
      Set.of(
          "bsh.",
          "com.mchange.v2.c3p0.",
          "com.rometools.rome.feed.impl.",
          "com.sun.syndication.feed.impl.",
          "org.apache.commons.beanutils.");
  private static final Set<String> DESERIALIZATION_TYPE_PREFIXES =
      Set.of(
          "org.apache.commons.collections.functors.",
          "org.apache.commons.collections4.functors.",
          "org.codehaus.groovy.runtime.",
          "com.sun.org.apache.xpath.internal.",
          "com.sun.org.apache.xml.internal.",
          "com.sun.jndi.",
          "com.sun.xml.internal.ws.",
          "sun.rmi.");
  private static final Set<String> POLYMORPHIC_CONSTRUCTION_BLACKLIST =
      Set.of("org.h2.jdbc.JdbcConnection");
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
  private static final Set<String> EXPRESSION_ENGINES =
      Set.of(
          "spel",
          "ognl",
          "mvel",
          "xpath",
          "template",
          "javascript",
          "jiffle",
          "groovy",
          "script",
          "jexl",
          "el",
          "expression");
  private static final Set<String> BEAN_POLLUTION_TARGETS =
      Set.of(
          "resources.context.parent.pipeline",
          "protectiondomain.codesource.location",
          "ucp.path",
          "urlclassloader",
          "systemclassloader");
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
    if (looksLikeInternalIdentityBypass(userAgent, request)) {
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_identity",
              90,
              "Request presents an internal service identity on a sensitive control path",
              request,
              Map.of(
                  "userAgent", userAgent,
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<JwtDefaultSecretMatch> defaultJwt = defaultJwtSecretMatch(request);
    if (defaultJwt.isPresent()) {
      JwtDefaultSecretMatch match = defaultJwt.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_default_jwt_secret",
              95,
              "Bearer JWT is signed with a known default HMAC secret",
              request,
              Map.of(
                  "keyId", match.keyId(),
                  "algorithm", match.algorithm(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DefaultEncryptedCookieMatch> defaultCookie = defaultEncryptedCookieMatch(request);
    if (defaultCookie.isPresent()) {
      DefaultEncryptedCookieMatch match = defaultCookie.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_default_crypto_cookie",
              95,
              "Encrypted cookie contains a Java object stream under a known default key",
              request,
              Map.of(
                  "cookieName", match.cookieName(),
                  "keyId", match.keyId(),
                  "cipher", match.cipher(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<SerializedClientStateMatch> serializedClientState = serializedClientState(request);
    if (serializedClientState.isPresent()) {
      SerializedClientStateMatch match = serializedClientState.orElseThrow();
      RequestContext redactedRequest = redactSerializedClientStateRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_serialized_client_state",
              92,
              "Client-side state parameter carries a Java serialized object stream",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "encoding", match.encoding(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "payloadLength", String.valueOf(match.payloadLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DefaultCredentialMatch> defaultCredential = defaultCredentialAttempt(request);
    if (defaultCredential.isPresent()) {
      DefaultCredentialMatch match = defaultCredential.orElseThrow();
      RequestContext redactedRequest = redactCredentialRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_default_credential",
              88,
              "Request uses a known default administrative credential on a control path",
              redactedRequest,
              Map.of(
                  "credentialId", match.credentialId(),
                  "mechanism", match.mechanism(),
                  "username", match.username(),
                  "usernameSource", match.usernameSource(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<EmptyCredentialBypassMatch> emptyCredentials = emptyCredentialBypass(request);
    if (emptyCredentials.isPresent()) {
      EmptyCredentialBypassMatch match = emptyCredentials.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_empty_credential_bypass",
              90,
              "Request attempts control access with empty credentials and a bypass flag",
              request,
              Map.of(
                  "usernameParameter", match.usernameParameter(),
                  "passwordParameter", match.passwordParameter(),
                  "bypassParameter", match.bypassParameter(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<String> beanPollution = request.parameters().keySet().stream()
        .filter(DetectorEngine::looksLikeJavaBeanPollution)
        .findFirst();
    if (beanPollution.isPresent()) {
      RequestContext redactedRequest = redactJavaBeanPollutionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_java_bean_pollution",
              95,
              "Request parameter attempts to bind Java classloader metadata",
              redactedRequest,
              Map.of("parameter", abbreviate(beanPollution.orElseThrow()))));
    }
    Optional<SchedulerShellJobMatch> schedulerJob = schedulerShellJobDispatch(request);
    if (schedulerJob.isPresent()) {
      SchedulerShellJobMatch match = schedulerJob.orElseThrow();
      RequestContext redactedRequest = redactSchedulerShellJobRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_scheduler_shell_job",
              90,
              "Request dispatches a scheduler job with shell-backed source",
              redactedRequest,
              Map.of(
                  "typeParameter", match.typeParameter(),
                  "typeValue", abbreviate(match.typeValue()),
                  "sourceParameter", match.sourceParameter(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DebugProcessLaunchMatch> debugProcess = debugProcessLaunch(request);
    if (debugProcess.isPresent()) {
      DebugProcessLaunchMatch match = debugProcess.orElseThrow();
      RequestContext redactedRequest = redactDebugProcessLaunchRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_debug_process_launch",
              88,
              "Request invokes a debug process launch endpoint with an executable parameter",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "commandLength", String.valueOf(match.commandLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<DynamicScriptConfigMatch> dynamicConfig = dynamicScriptConfig(request);
    if (dynamicConfig.isPresent()) {
      DynamicScriptConfigMatch match = dynamicConfig.orElseThrow();
      RequestContext redactedRequest = redactDynamicScriptConfigRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_dynamic_script_config",
              90,
              "Request submits dynamic script configuration with runtime execution",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TemplateLoaderEnableMatch> templateLoaderEnable = templateLoaderEnable(request);
    if (templateLoaderEnable.isPresent()) {
      TemplateLoaderEnableMatch match = templateLoaderEnable.orElseThrow();
      RequestContext redactedRequest = redactTemplateLoaderEnableRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_loader_enable",
              88,
              "Request enables parameter-loaded template resources",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<MessageSelectorExpressionMatch> messageSelectorExpression =
        messageSelectorExpression(request);
    if (messageSelectorExpression.isPresent()) {
      MessageSelectorExpressionMatch match = messageSelectorExpression.orElseThrow();
      RequestContext redactedRequest = redactBodyRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_message_selector_expression",
              92,
              "Request message selector carries a runtime expression",
              redactedRequest,
              Map.of(
                  "engine", match.engine(),
                  "selectorLength", String.valueOf(match.selectorLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<ExpressionHeaderMatch> expressionHeader = expressionHeader(request);
    if (expressionHeader.isPresent()) {
      ExpressionHeaderMatch match = expressionHeader.orElseThrow();
      RequestContext redactedRequest = redactExpressionHeaderRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_header",
              90,
              "Request header carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "header", match.header(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestJndiLookupMatch> jndiLookup = requestJndiLookup(request);
    if (jndiLookup.isPresent()) {
      RequestJndiLookupMatch match = jndiLookup.orElseThrow();
      RequestContext redactedRequest = redactJndiLookupRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_jndi_lookup",
              95,
              "Request carries a JNDI lookup payload",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "name", match.name(),
                  "protocol", match.protocol(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TemplateParameterMatch> templateParameter = templateParameter(request);
    if (templateParameter.isPresent()) {
      TemplateParameterMatch match = templateParameter.orElseThrow();
      RequestContext redactedRequest = redactTemplateParameterRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_parameter",
              90,
              "Request parameter carries a runtime template payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TemplateSourceMatch> templateSource = templateSource(request);
    if (templateSource.isPresent()) {
      TemplateSourceMatch match = templateSource.orElseThrow();
      RequestContext redactedRequest = redactTemplateSourceRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_template_source",
              88,
              "Request selects an unsafe template source path or URL",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "targetType", match.targetType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestExpressionParameterMatch> expressionParameter =
        requestExpressionParameter(request);
    if (expressionParameter.isPresent()) {
      RequestExpressionParameterMatch match = expressionParameter.orElseThrow();
      RequestContext redactedRequest = redactExpressionParameterRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_parameter",
              90,
              "Request parameter carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<JsonPatchExpressionMatch> jsonPatchExpression = jsonPatchExpression(request);
    if (jsonPatchExpression.isPresent()) {
      JsonPatchExpressionMatch match = jsonPatchExpression.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_json_patch_expression",
              90,
              "JSON Patch path carries a runtime expression payload",
              request,
              Map.of(
                  "field", "path",
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "bodyLength", String.valueOf(match.bodyLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestExpressionParameterNameMatch> expressionParameterName =
        requestExpressionParameterName(request);
    if (expressionParameterName.isPresent()) {
      RequestExpressionParameterNameMatch match = expressionParameterName.orElseThrow();
      RequestContext redactedRequest = redactExpressionParameterNameRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_parameter_name",
              90,
              "Request parameter name carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RequestExpressionPathMatch> expressionPath = requestExpressionPath(request);
    if (expressionPath.isPresent()) {
      RequestExpressionPathMatch match = expressionPath.orElseThrow();
      RequestContext redactedRequest = redactExpressionPathRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_expression_path",
              90,
              "Request path carries a runtime expression payload",
              redactedRequest,
              Map.of(
                  "engine", match.engine(),
                  "expressionLength", String.valueOf(match.expressionLength()),
                  "uri", redactedRequest.uri(),
                  "method", request.method())));
    }
    Optional<RequestXxePayloadMatch> xxePayload = requestXxePayload(request);
    if (xxePayload.isPresent()) {
      RequestXxePayloadMatch match = xxePayload.orElseThrow();
      RequestContext redactedRequest = redactXxePayloadRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_xxe_payload",
              90,
              "Request parameter carries an external XML entity payload",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "scheme", match.scheme(),
                  "xmlLength", String.valueOf(match.xmlLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TypedParameterDeserializationMatch> typedParameter =
        typedParameterDeserialization(request);
    if (typedParameter.isPresent()) {
      TypedParameterDeserializationMatch match = typedParameter.orElseThrow();
      RequestContext redactedRequest = redactTypedParameterDeserializationRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_typed_parameter_deserialization",
              92,
              "Request parameter declares a dangerous Java binding type",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "class", match.className(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<XmlPolymorphicGadgetPayloadMatch> xmlGadgetPayload =
        xmlPolymorphicGadgetPayload(request);
    if (xmlGadgetPayload.isPresent()) {
      XmlPolymorphicGadgetPayloadMatch match = xmlGadgetPayload.orElseThrow();
      RequestContext redactedRequest = redactBodyRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_xml_polymorphic_gadget",
              93,
              "XML request payload declares a dangerous polymorphic gadget type",
              redactedRequest,
              Map.of(
                  "class", match.className(),
                  "source", match.source(),
                  "bodyLength", String.valueOf(match.bodyLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<TypedPayloadDeserializationMatch> typedPayload =
        typedPayloadDeserialization(request);
    if (typedPayload.isPresent()) {
      TypedPayloadDeserializationMatch match = typedPayload.orElseThrow();
      RequestContext redactedRequest = redactTypedPayloadDeserializationRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_typed_payload_deserialization",
              92,
              "Request payload declares a dangerous Java binding type",
              redactedRequest,
              Map.of(
                  "source", match.source(),
                  "parameter", match.parameter(),
                  "class", match.className(),
                  "trigger", match.trigger(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RemoteContentStreamMatch> remoteContentStream = remoteContentStream(request);
    if (remoteContentStream.isPresent()) {
      RemoteContentStreamMatch match = remoteContentStream.orElseThrow();
      RequestContext redactedRequest = redactRemoteContentStreamRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_content_stream",
              88,
              "Request enables or uses unsafe remote content streaming",
              redactedRequest,
              Map.of(
                  "mode", match.mode(),
                  "parameter", match.parameter(),
                  "scheme", match.scheme(),
                  "sourceLength", String.valueOf(match.sourceLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RemoteImportScriptWriteMatch> remoteImportScriptWrite =
        remoteImportScriptWrite(request);
    if (remoteImportScriptWrite.isPresent()) {
      RemoteImportScriptWriteMatch match = remoteImportScriptWrite.orElseThrow();
      RequestContext redactedRequest = redactRemoteImportScriptWriteRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_import_script_write",
              90,
              "Request imports remote content into a server-side script target",
              redactedRequest,
              Map.of(
                  "sourceParameter", match.sourceParameter(),
                  "targetParameter", match.targetParameter(),
                  "targetType", match.targetType(),
                  "remoteSourceCount", String.valueOf(match.remoteSourceCount()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<RepositoryWebrootWriteMatch> repositoryWebrootWrite =
        repositoryWebrootWrite(request);
    if (repositoryWebrootWrite.isPresent()) {
      RepositoryWebrootWriteMatch match = repositoryWebrootWrite.orElseThrow();
      RequestContext redactedRequest = redactRepositoryWebrootWriteRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_repository_webroot_write",
              90,
              "Request configures repository persistence into a web-executable location",
              redactedRequest,
              Map.of(
                  "targetParameter", match.targetParameter(),
                  "targetType", match.targetType(),
                  "locationType", match.locationType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<PlotCommandInjectionMatch> plotCommandInjection = plotCommandInjection(request);
    if (plotCommandInjection.isPresent()) {
      PlotCommandInjectionMatch match = plotCommandInjection.orElseThrow();
      RequestContext redactedRequest = redactPlotCommandInjectionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_plot_command_injection",
              90,
              "Request plotting parameter carries an interpreter command directive",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<SqlSortInjectionMatch> sqlSortInjection = sqlSortInjection(request);
    if (sqlSortInjection.isPresent()) {
      SqlSortInjectionMatch match = sqlSortInjection.orElseThrow();
      RequestContext redactedRequest = redactSqlSortInjectionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_sql_sort_injection",
              90,
              "Request JSON sort field carries a SQL control expression",
              redactedRequest,
              Map.of(
                  "field", match.field(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<SqlIdentifierInjectionMatch> sqlIdentifierInjection =
        sqlIdentifierInjection(request);
    if (sqlIdentifierInjection.isPresent()) {
      SqlIdentifierInjectionMatch match = sqlIdentifierInjection.orElseThrow();
      RequestContext redactedRequest = redactBodyRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_sql_identifier_injection",
              90,
              "Request JSON identifier field carries a SQL control expression",
              redactedRequest,
              Map.of(
                  "field", match.field(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<OgcFilterSqlInjectionMatch> ogcFilterSqlInjection = ogcFilterSqlInjection(request);
    if (ogcFilterSqlInjection.isPresent()) {
      OgcFilterSqlInjectionMatch match = ogcFilterSqlInjection.orElseThrow();
      RequestContext redactedRequest = redactOgcFilterSqlInjectionRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_ogc_filter_sql_injection",
              90,
              "Request OGC filter carries a SQL control expression",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<SetupStateResetMatch> setupStateReset = setupStateReset(request);
    if (setupStateReset.isPresent()) {
      SetupStateResetMatch match = setupStateReset.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_setup_state_reset",
              90,
              "Request parameter attempts to reset application setup completion state",
              request,
              Map.of(
                  "parameter", abbreviate(match.parameter()),
                  "value", match.value(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<ServerSideScriptPutMatch> scriptPut = serverSideScriptPut(request);
    if (scriptPut.isPresent()) {
      ServerSideScriptPutMatch match = scriptPut.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_server_side_script_put",
              90,
              "HTTP PUT targets a server-side script path",
              request,
              Map.of(
                  "path", abbreviate(match.path()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<UploadFilenameOverrideMatch> uploadFilenameOverride =
        uploadFilenameOverride(request);
    if (uploadFilenameOverride.isPresent()) {
      UploadFilenameOverrideMatch match = uploadFilenameOverride.orElseThrow();
      RequestContext redactedRequest = redactUploadFilenameOverrideRequest(request);
      return Optional.of(
          Detection.log(
              "request",
              "request_upload_filename_override",
              90,
              "Multipart request overrides upload filename binding with an unsafe path",
              redactedRequest,
              Map.of(
                  "parameter", match.parameter(),
                  "targetType", match.targetType(),
                  "valueLength", String.valueOf(match.valueLength()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<Map.Entry<String, String>> internalForward = requestControlledInternalForward(request);
    if (internalForward.isPresent()) {
      Map.Entry<String, String> forward = internalForward.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_forward",
              90,
              "Request parameter attempts internal forwarding to a sensitive control path",
              request,
              Map.of(
                  "parameter", forward.getKey(),
                  "target", abbreviate(forward.getValue()),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<InternalResourceMatch> internalResource = protectedInternalResourceRequest(request);
    if (internalResource.isPresent()) {
      InternalResourceMatch match = internalResource.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_internal_resource",
              88,
              "Request target exposes a protected web application resource after decoding",
              request,
              Map.of(
                  "component", match.component(),
                  "resource", match.resource(),
                  "variant", match.variant(),
                  "uri", abbreviate(request.uri()),
                  "method", request.method())));
    }
    Optional<String> confusingPath = confusingRequestPath(request.uri());
    if (confusingPath.isPresent()) {
      return Optional.of(
          Detection.log(
              "request",
              "request_path_confusion",
              90,
              "Request URI contains path normalization confusion",
              request,
              Map.of(
                  "uri", abbreviate(request.uri()),
                  "decoded", abbreviate(confusingPath.orElseThrow()))));
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

  public Optional<Detection> detectServletIncludeAttributes(
      Map<String, String> attributes, RequestContext request, List<String> stackClassNames) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (attributes == null || attributes.isEmpty() || legitimateServletIncludeStack(stackClassNames)) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> entry : attributes.entrySet()) {
      String attribute = entry.getKey() == null ? "" : entry.getKey();
      String value = entry.getValue() == null ? "" : entry.getValue();
      if (!isServletIncludeAttribute(attribute) || value.isBlank()) {
        continue;
      }
      Optional<IncludeAttributeTarget> target = suspiciousIncludeAttributeTarget(value);
      if (target.isEmpty()) {
        continue;
      }
      IncludeAttributeTarget match = target.orElseThrow();
      return Optional.of(
          Detection.log(
              "request",
              "request_forged_include_attribute",
              92,
              "Top-level request carries forged servlet include attributes for a sensitive target",
              safeRequest,
              Map.of(
                  "attribute", abbreviate(attribute),
                  "targetType", match.type(),
                  "resource", match.resource(),
                  "source", "servlet-include-attribute",
                  "uri", abbreviate(safeRequest.uri()),
                  "method", safeRequest.method())));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectRemoteJobSubmission(
      String mechanism, String descriptor, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    String safeDescriptor = descriptor == null ? "" : descriptor;
    if (safeDescriptor.isBlank()
        || !safeRequest.active()
        || !remoteJobSubmissionContext(safeRequest, mechanism, safeDescriptor)) {
      return Optional.empty();
    }
    var artifact = REMOTE_JOB_ARTIFACT.matcher(safeDescriptor);
    if (artifact.find() && REMOTE_JOB_MAIN_CLASS.matcher(safeDescriptor).find()) {
      String artifactUrl = artifact.group(1);
      return Optional.of(
          Detection.log(
              "request",
              "request_remote_job_submission",
              92,
              "Request submits a remote executable artifact to a job control endpoint",
              safeRequest,
              Map.of(
                  "mechanism", abbreviate(mechanism),
                  "uri", abbreviate(safeRequest.uri()),
                  "method", safeRequest.method(),
                  "descriptorLength", String.valueOf(safeDescriptor.length()),
                  "artifactScheme", protocolOf(artifactUrl),
                  "artifactType", extensionOf(artifactUrl))));
    }
    var command = REMOTE_JOB_COMMAND_VALUE.matcher(safeDescriptor);
    while (command.find()) {
      String value = command.group(1);
      if (dangerousRemoteJobCommand(value)) {
        return Optional.of(
            Detection.log(
                "request",
                "request_remote_job_submission",
                95,
                "Request submits a shell command to a job control endpoint",
                safeRequest,
                Map.of(
                    "mechanism", abbreviate(mechanism),
                    "uri", abbreviate(safeRequest.uri()),
                    "method", safeRequest.method(),
                    "descriptorLength", String.valueOf(safeDescriptor.length()),
                    "commandLength", String.valueOf(value.length()))));
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
    if (h2DangerousSql(query)) {
      return Optional.of(
          Detection.log(
              "sql",
              "sql_h2_code_execution",
              95,
              "H2 SQL attempts to load script or executable Java code",
              request,
              Map.of("query", abbreviate(query))));
    }
    if (request.active() && DERBY_CODE_LOADING.matcher(query).find()) {
      boolean requestControlled = request.hasParameterIn(query);
      return Optional.of(
          Detection.log(
              "sql",
              "sql_derby_code_execution",
              requestControlled ? 95 : 90,
              "Derby SQL attempts to load Java code or mutate the database classpath",
              request,
              Map.of(
                  "query", abbreviate(query),
                  "requestControlled", String.valueOf(requestControlled))));
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

  public Optional<Detection> detectJdbcUrl(String url, RequestContext request) {
    if (url == null || url.isBlank()) {
      return Optional.empty();
    }
    String normalized = lower(url);
    if (normalized.startsWith("jdbc:h2:")
        && H2_INIT_SETTING.matcher(url).find()
        && h2DangerousSql(url)) {
      return Optional.of(
          Detection.log(
              "jdbc",
              "jdbc_h2_init",
              95,
              "H2 JDBC URL uses INIT to load script or executable Java code",
              request,
              Map.of("url", abbreviate(url))));
    }
    if (mysqlJdbcDeserializationUrl(url, request)) {
      return Optional.of(
          Detection.log(
              "jdbc",
              "jdbc_mysql_deserialization",
              95,
              "Request-controlled MySQL JDBC URL enables connector deserialization behavior",
              request,
              Map.of("url", abbreviate(url), "driver", mysqlJdbcDriver(normalized))));
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
    String expressionEngine = expressionEngineFromStack(stackClassNames);
    if (!expressionEngine.isBlank()) {
      String algorithm = expressionRuntimeAlgorithm(expressionEngine);
      return Optional.of(
          Detection.log(
              expressionEngine,
              algorithm,
              95,
              "Command execution reached from dynamic expression evaluation",
              request,
              Map.of("command", abbreviate(joined))));
    }
    Optional<String> executableListener = executableListenerFrame(stackClassNames);
    if (executableListener.isPresent()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_config_listener",
              90,
              "Command execution reached from a server-configured executable listener",
              request,
              Map.of(
                  "command", abbreviate(joined),
                  "listener", abbreviate(executableListener.orElseThrow()))));
    }
    Optional<String> configLauncher = configCommandLauncherFrame(stackClassNames);
    if (configLauncher.isPresent()) {
      return Optional.of(
          Detection.log(
              "command",
              "command_config_injection",
              90,
              "Command execution reached from mutable runtime configuration",
              request,
              Map.of(
                  "command", abbreviate(joined),
                  "launcher", abbreviate(configLauncher.orElseThrow()))));
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

  public Optional<Detection> detectXmlAttachmentReference(
      String mechanism, String rawHref, RequestContext request) {
    if (rawHref == null || rawHref.isBlank() || request == null || !request.active()) {
      return Optional.empty();
    }
    String hook = xmlAttachmentMechanism(mechanism);
    if (hook.isBlank()) {
      return Optional.empty();
    }
    String href = attachmentHref(rawHref);
    if (href.isBlank()) {
      return Optional.empty();
    }
    URI uri;
    try {
      uri = URI.create(href);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    String scheme = lower(uri.getScheme());
    String host = lower(uri.getHost());
    String path = lower(uri.getPath());
    if (isLocalClasspathResource(href, scheme, path)) {
      return Optional.empty();
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_protocol",
              95,
              "XML attachment reference uses a dangerous protocol: " + scheme,
              request,
              Map.of("mechanism", hook, "scheme", scheme, "href", abbreviate(href))));
    }
    if (!scheme.equals("http") && !scheme.equals("https")) {
      return Optional.empty();
    }
    if (host.contains("169.254.169.254") || path.contains("/latest/meta-data")) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_aws",
              100,
              "XML attachment reference targets cloud instance metadata",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (isInternalHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_userinput",
              95,
              "XML attachment reference targets an internal address",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (DNSLOG_DOMAIN.matcher(host).matches()) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_common",
              90,
              "XML attachment reference targets a callback collection domain",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    if (looksObfuscatedHost(host)) {
      return Optional.of(
          Detection.log(
              "ssrf",
              "ssrf_obfuscate",
              85,
              "XML attachment reference host appears obfuscated",
              request,
              Map.of("mechanism", hook, "host", host, "href", abbreviate(href))));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectClassLoaderUrl(
      String rawUrl, String mechanism, RequestContext request) {
    if (rawUrl == null || rawUrl.isBlank()) {
      return Optional.empty();
    }
    String normalized = rawUrl.trim();
    String inspected = lower(normalized);
    if (inspected.startsWith("jar:")) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    String scheme;
    try {
      scheme = lower(URI.create(inspected).getScheme());
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    if (!REMOTE_CLASSLOADER_PROTOCOLS.contains(scheme)) {
      return Optional.empty();
    }
    String hook = mechanism == null || mechanism.isBlank() ? "classloader" : mechanism;
    int confidence = request.hasParameterIn(normalized) ? 100 : 90;
    return Optional.of(
        Detection.log(
            "classloader",
            "classloader_remote",
            confidence,
            "Class loader is configured with a remote codebase URL",
            request,
            Map.of(
                "mechanism", hook,
                "scheme", scheme,
                "url", abbreviate(normalized),
                "requestControlled", String.valueOf(request.hasParameterIn(normalized)))));
  }

  public Optional<Detection> detectSpringConfigLocation(
      String location, String mechanism, RequestContext request) {
    if (location == null || location.isBlank()) {
      return Optional.empty();
    }
    String normalized = location.trim();
    Optional<String> remoteScheme = remoteConfigScheme(normalized);
    if (remoteScheme.isEmpty()) {
      return Optional.empty();
    }
    String scheme = remoteScheme.orElseThrow();
    String hook = mechanism == null || mechanism.isBlank() ? "spring" : mechanism;
    int confidence = request.hasParameterIn(normalized) ? 100 : 90;
    return Optional.of(
        Detection.log(
            "spring",
            "spring_remote_config",
            confidence,
            "Spring configuration is loaded from a remote resource",
            request,
            Map.of(
                "mechanism", hook,
                "scheme", scheme,
                "location", abbreviate(normalized),
                "requestControlled", String.valueOf(request.hasParameterIn(normalized)))));
  }

  public Optional<Detection> detectJmxMBeanInvoke(
      String mbeanName, String operationName, List<String> arguments, RequestContext request) {
    if (operationName == null || operationName.isBlank() || !request.active()) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    Optional<String> remoteConfig =
        safeArguments.stream()
            .filter(argument -> argument != null && looksLikeRemoteJmxConfig(argument))
            .findFirst();
    if (!isMutatingJmxOperation(operationName)) {
      return Optional.empty();
    }
    if (remoteConfig.isPresent()) {
      String matched = remoteConfig.orElseThrow();
      int confidence = request.hasParameterIn(matched) ? 100 : 90;
      return Optional.of(
          Detection.log(
              "jmx",
              "jmx_remote_config",
              confidence,
              "Request-time MBean invocation passes a remote configuration source",
              request,
              Map.of(
                  "mbean", abbreviate(String.valueOf(mbeanName)),
                  "operation", operationName,
                  "argument", abbreviate(matched),
                  "requestControlled", String.valueOf(request.hasParameterIn(matched)))));
    }
    Optional<String> scriptTarget = safeArguments.stream()
        .map(DetectorEngine::jmxScriptWriteTarget)
        .flatMap(Optional::stream)
        .findFirst();
    if (scriptTarget.isEmpty()) {
      return Optional.empty();
    }
    String matched = scriptTarget.orElseThrow();
    int confidence = request.hasParameterIn(matched) ? 100 : 90;
    return Optional.of(
        Detection.log(
            "jmx",
            "jmx_file_write",
            confidence,
            "Request-time MBean invocation writes a server-side script target",
            request,
            Map.of(
                "mbean", abbreviate(String.valueOf(mbeanName)),
                "operation", operationName,
                "path", abbreviate(matched),
                "requestControlled", String.valueOf(request.hasParameterIn(matched)))));
  }

  public Optional<Detection> detectArgumentFileExpansion(
      String parser, List<String> arguments, RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String normalizedParser = lower(parser);
    if (!normalizedParser.equals("args4j")) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    for (String argument : safeArguments) {
      Optional<String> target = argumentFileExpansionTarget(argument);
      if (target.isEmpty()) {
        continue;
      }
      String path = target.orElseThrow();
      if (!dangerousArgumentFilePath(path)) {
        continue;
      }
      String normalizedPath = normalizePath(path);
      int confidence =
          request.hasParameterIn(argument)
                  || request.hasParameterIn(path)
                  || request.hasParameterIn(normalizedPath)
              ? 100
              : 95;
      return Optional.of(
          Detection.log(
              "readFile",
              "readFile_argument_expansion",
              confidence,
              "Command argument parser expands an @file reference during a request",
              request,
              Map.of(
                  "parser", normalizedParser,
                  "argument", abbreviate(argument),
                  "path", abbreviate(normalizedPath))));
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
    Optional<String> configPersistence = configPersistenceFrame(stackClassNames);
    if (configPersistence.isPresent() && unsafeConfigPersistencePath(normalized)) {
      return Optional.of(
          Detection.log(
              "writeFile",
              "writeFile_config_path",
              85,
              "Runtime configuration persistence wrote to an unsafe path",
              request,
              Map.of(
                  "path", normalized,
                  "persistence", abbreviate(configPersistence.orElseThrow()))));
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

  public Optional<Detection> detectArchiveExtraction(
      String entryName, String targetPath, RequestContext request) {
    String entry = archivePath(entryName);
    String target = archivePath(targetPath);
    if (entry.isBlank() || target.isBlank() || !dangerousArchiveEntry(entry)) {
      return Optional.empty();
    }
    if (!targetUsesDangerousArchiveEntry(entry, target)) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "archive",
            "archive_traversal",
            95,
            "Archive extraction target escapes the intended directory",
            request,
            Map.of("entry", abbreviate(entryName), "target", abbreviate(targetPath))));
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
    Optional<String> expressionEngine = dangerousUploadExpressionFilename(filename);
    if (expressionEngine.isPresent()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_multipart_expression",
              95,
              "Multipart upload filename contains a dangerous expression payload",
              request,
              Map.of(
                  "engine", expressionEngine.orElseThrow(),
                  "filenameLength", String.valueOf(filename == null ? 0 : filename.length()))));
    }
    if (dangerousUploadFilename(filename)) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_path_traversal",
              95,
              "Multipart upload filename escapes the intended upload directory",
              request,
              Map.of("filename", abbreviate(filename))));
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
    Optional<String> javaArchiveContext = javaArchiveUploadContext(request);
    if (JAVA_ARCHIVE_FILE.matcher(normalized).matches() && javaArchiveContext.isPresent()) {
      return Optional.of(
          Detection.log(
              "fileUpload",
              "fileUpload_java_archive",
              90,
              "Multipart upload contains a Java executable archive for a deployment endpoint",
              request,
              Map.of(
                  "filename", normalized,
                  "context", abbreviate(javaArchiveContext.orElseThrow()))));
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

  private static Optional<String> dangerousUploadExpressionFilename(String filename) {
    if (filename == null || filename.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(filename)) {
      String engine = requestExpressionParameterEngine(variant);
      if (engine.isBlank()) {
        continue;
      }
      if (dangerousRequestExpressionValue(engine, variant)
          || dangerousParserHeaderExpression(engine, variant)) {
        return Optional.of(engine);
      }
    }
    return Optional.empty();
  }

  public Optional<Detection> detectWebdavUpload(
      String source, String destination, String method, RequestContext request) {
    if (!webdavMutationMethod(method)) {
      return Optional.empty();
    }
    String normalizedSource = normalizePath(source);
    String normalizedDestination = normalizePath(destination);
    String destinationPath = webdavDestinationPath(destination);
    if (!SCRIPT_FILE.matcher(normalizedSource).matches()
        && (SCRIPT_FILE.matcher(normalizedDestination).matches()
            || SCRIPT_FILE.matcher(destinationPath).matches())) {
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
                  "destinationType", "server-side-script",
                  "method", String.valueOf(method))));
    }
    if (unsafeWebdavDestination(destination, destinationPath)) {
      return Optional.of(
          Detection.log(
              "webdav",
              "fileUpload_webdav",
              95,
              "WebDAV-style move writes to an unsafe filesystem destination",
              request,
              Map.of(
                  "source", normalizedSource,
                  "destination", normalizedDestination,
                  "destinationPath", destinationPath,
                  "destinationType", "unsafe-filesystem-path",
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

  public Optional<Detection> detectJaasConfig(
      String config, String mechanism, RequestContext request) {
    if (config == null || config.isBlank() || !request.active()) {
      return Optional.empty();
    }
    String normalized = config.trim();
    if (!JAAS_JNDI_LOGIN_MODULE.matcher(normalized).find()) {
      return Optional.empty();
    }
    var provider = JAAS_REMOTE_PROVIDER_URL.matcher(normalized);
    if (!provider.find()) {
      return Optional.empty();
    }
    String providerUrl = provider.group(1);
    String hook = mechanism == null || mechanism.isBlank() ? "JAAS" : mechanism;
    boolean requestControlled =
        request.hasParameterIn(normalized) || request.hasParameterIn(providerUrl);
    return Optional.of(
        Detection.log(
            "jndi",
            "jndi_jaas_config",
            requestControlled ? 100 : 90,
            "JAAS configuration enables JNDI login module with a remote provider URL",
            request,
            Map.of(
                "mechanism", hook,
                "providerUrl", abbreviate(providerUrl),
                "config", abbreviate(normalized),
                "requestControlled", String.valueOf(requestControlled))));
  }

  public Optional<Detection> detectJwtVerificationFailure(
      String mechanism, String exceptionClass, String message, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active() || !jwtVerificationFailureType(exceptionClass, message)) {
      return Optional.empty();
    }
    Optional<JwtTokenSource> tokenSource = jwtTokenSource(safeRequest);
    if (tokenSource.isEmpty() || !jwtVerificationRequestContext(safeRequest, tokenSource.orElseThrow())) {
      return Optional.empty();
    }
    String hook = mechanism == null || mechanism.isBlank() ? "jwt" : mechanism;
    RequestContext redactedRequest =
        redactJwtTokenRequest(safeRequest, tokenSource.orElseThrow().source());
    return Optional.of(
        Detection.log(
            "request",
            "request_jwt_verification_failure",
            95,
            "JWT verification failed during request authentication",
            redactedRequest,
            Map.of(
                "mechanism", abbreviate(hook),
                "exception", abbreviate(exceptionClass),
                "tokenSource", tokenSource.orElseThrow().source(),
                "method", redactedRequest.method(),
                "uri", abbreviate(redactedRequest.uri()))));
  }

  public Optional<Detection> detectDeserialization(String className, RequestContext request) {
    return detectDeserialization(className, request, List.of());
  }

  public Optional<Detection> detectDeserialization(
      String className, RequestContext request, List<String> stackClassNames) {
    if (className == null || className.isBlank()) {
      return Optional.empty();
    }
    String normalized = normalizeJavaTypeName(className);
    Optional<String> signedObjectTransport = signedObjectRemotingFrame(stackClassNames);
    if (normalized.equals("java.security.SignedObject") && signedObjectTransport.isPresent()) {
      return Optional.of(
          Detection.log(
              "deserialization",
              "deserialization_signed_object",
              95,
              "Remote CLI/remoting transport deserialized a SignedObject wrapper",
              request,
              Map.of(
                  "class", normalized,
                  "transport", signedObjectTransport.orElseThrow())));
    }
    if (dangerousDeserializationType(normalized)) {
      Optional<String> webflowState = webflowClientStateFrame(stackClassNames);
      if (webflowState.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_webflow_state",
                95,
                "WebFlow client state deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", webflowState.orElseThrow())));
      }
	      Optional<String> clusterTransport = clusterMessageTransportFrame(stackClassNames);
	      if (clusterTransport.isPresent()) {
	        Map<String, String> details = new LinkedHashMap<>();
	        details.put("class", normalized);
	        details.put("transport", clusterTransport.orElseThrow());
	        clusterSecurityInterceptorFrame(stackClassNames)
	            .ifPresent(interceptor -> details.put("securityInterceptor", interceptor));
	        return Optional.of(
	            Detection.log(
	                "deserialization",
	                "deserialization_cluster_message",
	                95,
	                "Cluster/message transport deserialized a dangerous gadget class",
	                request,
	                details));
	      }
      Optional<String> loggingTransport = loggingMessageTransportFrame(stackClassNames);
      if (loggingTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_logging_message",
                95,
                "Logging transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", loggingTransport.orElseThrow())));
      }
      Optional<String> rmiTransport = rmiTransportFrame(stackClassNames);
      if (rmiTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_rmi_transport",
                95,
                "RMI transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", rmiTransport.orElseThrow())));
      }
      Optional<String> remotingTransport = remotingTransportFrame(stackClassNames);
      if (remotingTransport.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_remoting_transport",
                95,
                "Application remoting transport deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", remotingTransport.orElseThrow())));
      }
      Optional<String> jmsObjectMessage = jmsObjectMessageFrame(stackClassNames);
      if (jmsObjectMessage.isPresent()) {
        return Optional.of(
            Detection.log(
                "deserialization",
                "deserialization_jms_object_message",
                95,
                "JMS ObjectMessage deserialized a dangerous gadget class",
                request,
                Map.of(
                    "class", normalized,
                    "transport", jmsObjectMessage.orElseThrow())));
      }
      boolean gadgetFamily = deserializationGadgetType(normalized);
      return Optional.of(
          Detection.log(
              "deserialization",
              gadgetFamily ? "deserialization_gadget" : "deserialization_blacklist",
              gadgetFamily ? 95 : 100,
              (gadgetFamily
                      ? "Deserialization gadget family matched class "
                      : "Deserialization blacklist matched class ")
                  + normalized,
              request,
              Map.of("class", normalized)));
    }
    return Optional.empty();
  }

  public Optional<Detection> detectRmiRegistryBind(
      String operation,
      String bindingName,
      String remoteClassName,
      RequestContext request,
      List<String> stackClassNames) {
    String normalizedOperation = lower(operation).replaceAll("[^a-z]", "");
    if (!normalizedOperation.equals("bind") && !normalizedOperation.equals("rebind")) {
      return Optional.empty();
    }
    String normalizedRemoteClass = normalizeJavaTypeName(remoteClassName);
    if (!suspiciousRmiRemoteBindType(normalizedRemoteClass)
        || !rmiRegistryTransportStack(stackClassNames)) {
      return Optional.empty();
    }
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_rmi_registry_bind",
            95,
            "RMI Registry bind receives a remote proxy/reference through transport dispatch",
            safeRequest,
            Map.of(
                "operation", normalizedOperation,
                "binding", abbreviate(bindingName),
                "remoteClass", abbreviate(normalizedRemoteClass),
                "source", "rmi-transport")));
  }

  public Optional<Detection> detectSessionDeserialization(
      String sessionId, String mechanism, RequestContext request) {
    if (sessionId == null || sessionId.isBlank()) {
      return Optional.empty();
    }
    String normalized = sessionId.trim();
    if (!suspiciousFileBackedSessionId(normalized)) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "session" : mechanism;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_session_file",
            request.active() ? 95 : 90,
            "File-backed session deserialization uses a suspicious session identifier",
            request,
            Map.of(
                "sessionId", abbreviate(normalized),
                "mechanism", source)));
  }

  public Optional<Detection> detectPolymorphicType(
      String parser, String className, RequestContext request) {
    if (className == null || className.isBlank()) {
      return Optional.empty();
    }
    String normalized = normalizeJavaTypeName(className);
    if (!dangerousPolymorphicType(normalized)) {
      return Optional.empty();
    }
    int confidence = request.hasParameterIn(className) || request.hasParameterIn(normalized) ? 100 : 95;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_polymorphic_type",
            confidence,
            "Polymorphic deserialization attempted to resolve a dangerous type",
            request,
            Map.of(
                "parser", String.valueOf(parser),
                "class", normalized,
                "originalClass", abbreviate(className))));
  }

  public Optional<Detection> detectProtocolClassInstantiation(
      String protocol, String className, List<String> arguments, RequestContext request) {
    String mechanism = protocol == null ? "" : protocol.trim();
    if (mechanism.isBlank() || className == null || className.isBlank()) {
      return Optional.empty();
    }
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    String normalized = normalizeJavaTypeName(className);
    if (!dangerousProtocolInstantiationType(normalized)) {
      return Optional.empty();
    }
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    Optional<String> remoteArgument = remoteConfigArgument(safeArguments);
    boolean requestControlled =
        safeRequest.hasParameterIn(className)
            || safeRequest.hasParameterIn(normalized)
            || remoteArgument.filter(safeRequest::hasParameterIn).isPresent();
    int confidence = requestControlled ? 100 : remoteArgument.isPresent() ? 98 : 95;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_protocol_class",
            confidence,
            "Protocol unmarshalling attempted to instantiate a dangerous class",
            safeRequest,
            Map.of(
                "protocol", mechanism,
                "class", normalized,
                "originalClass", abbreviate(className),
                "argument", abbreviate(remoteArgument.orElse("")),
                "remoteConfigScheme",
                    remoteArgument.flatMap(DetectorEngine::remoteConfigScheme).orElse(""),
                "requestControlled", String.valueOf(requestControlled))));
  }

  public Optional<Detection> detectHttpInvokerDeserialization(
      String mechanism, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "SpringHttpInvoker" : mechanism;
    String contentType = safeRequest.header("content-type").orElse("");
    String normalizedContentType = lower(contentType);
    int confidence =
        normalizedContentType.contains("application/x-java-serialized-object")
            ? 98
            : (normalizedContentType.contains("application/x-java")
                    || normalizedContentType.contains("application/octet-stream"))
                ? 95
                : 90;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_http_invoker",
            confidence,
            "HTTP remote invocation endpoint is deserializing a Java object stream",
            safeRequest,
            Map.of(
                "mechanism", source,
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  public Optional<Detection> detectHttpObjectStreamDeserialization(
      String streamClassName, RequestContext request, List<String> stackClassNames) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source =
        httpObjectStreamSource(
            streamClassName, safeRequest.header("content-type").orElse(""), stackClassNames);
    if (source.isBlank()) {
      return Optional.empty();
    }
    String contentType = safeRequest.header("content-type").orElse("");
    int confidence = "serialized-content-type".equals(source) ? 98 : 95;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_http_object_stream",
            confidence,
            "HTTP request body is being read through a Java ObjectInputStream",
            safeRequest,
            Map.of(
                "source", source,
                "streamClass", abbreviate(streamClassName),
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  public Optional<Detection> detectHessianType(String type, RequestContext request) {
    if (type == null || type.isBlank()) {
      return Optional.empty();
    }
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    String normalized = normalizeJavaTypeName(type);
    if (!dangerousHessianType(normalized)) {
      return Optional.empty();
    }
    boolean gadgetFamily = deserializationGadgetType(normalized);
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_hessian_type",
            safeRequest.active() ? 95 : 90,
            "Hessian RPC deserialization attempted to resolve a dangerous type",
            safeRequest,
            Map.of(
                "protocol", "hessian",
                "class", normalized,
                "originalClass", abbreviate(type),
                "gadgetFamily", String.valueOf(gadgetFamily))));
  }

  public Optional<Detection> detectXmlRpcSerializableValue(
      String mechanism, RequestContext request) {
    RequestContext safeRequest = request == null ? RequestContext.empty() : request;
    if (!safeRequest.active()) {
      return Optional.empty();
    }
    String source = mechanism == null || mechanism.isBlank() ? "ApacheXmlRpc" : mechanism;
    String contentType = safeRequest.header("content-type").orElse("");
    int confidence =
        lower(contentType).contains("xml")
            || safeRequest.uri().toLowerCase(Locale.ROOT).contains("xmlrpc")
            ? 98
            : 92;
    return Optional.of(
        Detection.log(
            "deserialization",
            "deserialization_xmlrpc_serialized",
            confidence,
            "XML-RPC request is deserializing a Java serialized extension value",
            safeRequest,
            Map.of(
                "mechanism", source,
                "method", safeRequest.method(),
                "uri", abbreviate(safeRequest.uri()),
                "contentType", abbreviate(contentType))));
  }

  public Optional<Detection> detectXmlDecoderExpression(
      String targetType,
      String methodName,
      List<String> arguments,
      RequestContext request,
      List<String> stackClassNames) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!isXmlDecoderStack(stackClassNames)) {
      return Optional.empty();
    }
    String normalizedTarget = normalizeJavaTypeName(targetType);
    String normalizedMethod = lower(methodName);
    List<String> safeArguments = arguments == null ? List.of() : arguments;
    String joinedArguments = String.join(" ", safeArguments);

    boolean processBuilderStart =
        normalizedTarget.equals("java.lang.ProcessBuilder") && normalizedMethod.equals("start");
    boolean runtimeExec =
        normalizedTarget.equals("java.lang.Runtime") && normalizedMethod.startsWith("exec");
    boolean reflectiveInvoke =
        normalizedTarget.equals("java.lang.reflect.Method") && normalizedMethod.equals("invoke");
    if (processBuilderStart || runtimeExec || reflectiveInvoke) {
      return Optional.of(
          Detection.log(
              "deserialization",
              "xml_decoder_runtime",
              95,
              "XMLDecoder object graph invoked a runtime execution primitive",
              request,
              Map.of(
                  "target", normalizedTarget,
                  "method", String.valueOf(methodName),
                  "arguments", abbreviate(joinedArguments))));
    }

    boolean writerConstruction =
        (normalizedTarget.equals("java.io.PrintWriter")
                || normalizedTarget.equals("java.io.FileWriter")
                || normalizedTarget.equals("java.io.FileOutputStream"))
            && (normalizedMethod.equals("new") || normalizedMethod.equals("newinstance"));
    if (writerConstruction) {
      for (String argument : safeArguments) {
        String path = normalizePath(argument);
        if (SCRIPT_FILE.matcher(path).matches()) {
          return Optional.of(
              Detection.log(
                  "deserialization",
                  "xml_decoder_webshell",
                  95,
                  "XMLDecoder object graph created a writer for a server-side script path",
                  request,
                  Map.of(
                      "target", normalizedTarget,
                      "method", String.valueOf(methodName),
                      "path", abbreviate(path))));
        }
      }
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

  public Optional<Detection> detectExpression(
      String engine, String expression, RequestContext request) {
    if (expression == null || expression.isBlank()) {
      return Optional.empty();
    }
    String normalizedEngine = lower(engine);
    if ("ognl".equals(normalizedEngine)) {
      return detectOgnl(expression, request);
    }
    if (!containsRuntimeExpressionPrimitive(normalizedEngine, expression)) {
      return Optional.empty();
    }
    String hook = EXPRESSION_ENGINES.contains(normalizedEngine) ? normalizedEngine : "expression";
    String algorithm =
        switch (hook) {
          case "spel" -> "spel_runtime";
          case "template" -> "template_runtime";
          case "javascript" -> "javascript_runtime";
          case "xpath" -> "xpath_runtime";
          case "jiffle" -> "jiffle_runtime";
          case "jexl" -> "jexl_runtime";
          case "el" -> "el_runtime";
          case "mvel", "groovy", "script" -> "script_runtime";
          default -> "expression_runtime";
        };
    int confidence = request.hasParameterIn(expression) ? 100 : 85;
    Map<String, String> details =
        "jiffle".equals(hook)
            ? Map.of(
                "engine", hook,
                "expressionLength", String.valueOf(expression.length()),
                "requestControlled", String.valueOf(request.hasParameterIn(expression)))
            : Map.of(
                "engine", hook,
                "expression", abbreviate(expression),
                "requestControlled", String.valueOf(request.hasParameterIn(expression)));
    return Optional.of(
        Detection.log(
            hook,
            algorithm,
            confidence,
            "Dynamic expression evaluates a runtime execution capability",
            request,
            details));
  }

  public Optional<Detection> detectJavaCompilation(
      String compiler, String source, RequestContext request) {
    if (source == null || source.isBlank()) {
      return Optional.empty();
    }
    boolean requestControlled = request.hasParameterIn(source);
    if (!requestControlled && !request.active()) {
      return Optional.empty();
    }
    String normalized = lower(source);
    String compact = normalized.replaceAll("\\s+", "");
    boolean runtimeExec =
        compact.contains("runtime.getruntime().exec")
            || (compact.contains("java.lang.runtime")
                && compact.contains("getruntime")
                && compact.contains(".exec"));
    boolean processBuilderStart =
        compact.contains("processbuilder")
            && (compact.contains(".start(") || compact.contains("getmethod(\"start\""));
    boolean scriptEngineEval =
        compact.contains("scriptenginemanager") && compact.contains(".eval(");
    if (!runtimeExec && !processBuilderStart && !scriptEngineEval) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "java_compile",
            "java_compile_runtime",
            requestControlled ? 100 : 85,
            "Java source compilation includes a runtime execution primitive",
            request,
            Map.of(
                "compiler", compiler == null || compiler.isBlank() ? "java" : compiler,
                "source", abbreviate(source),
                "requestControlled", String.valueOf(requestControlled))));
  }

  private static boolean isScriptEngine(String engine) {
    return "mvel".equals(engine)
        || "groovy".equals(engine)
        || "javascript".equals(engine)
        || "script".equals(engine);
  }

  private static boolean looksLikeScriptCommandExecution(String expression) {
    return SCRIPT_LITERAL_EXECUTE.matcher(expression).find()
        || SCRIPT_COMMAND_VARIABLE_EXECUTE.matcher(expression).find();
  }

  private static boolean containsRuntimeExpressionPrimitive(String engine, String expression) {
    String compactExpression = lower(expression).replaceAll("\\s+", "");
    boolean runtimeExec =
        compactExpression.contains("runtime")
            && compactExpression.contains("getruntime")
            && compactExpression.contains("exec");
    boolean reflectiveRuntimeExec =
        compactExpression.contains("java.lang.runtime")
            && (compactExpression.contains("getmethods") || compactExpression.contains("getmethod"))
            && compactExpression.contains("invoke")
            && compactExpression.contains("exec");
    boolean processBuilderStart =
        compactExpression.contains("processbuilder")
            && (compactExpression.contains(".start")
                || compactExpression.contains("newprocessbuilder")
                || compactExpression.contains("newjava.lang.processbuilder"));
    boolean reflectiveProcessBuilderStart =
        compactExpression.contains("processbuilder")
            && (compactExpression.contains("getmethod(\"start\"")
                || compactExpression.contains("getmethod('start'"))
            && compactExpression.contains("invoke");
    boolean scriptEngineEval =
        compactExpression.contains("scriptenginemanager") && compactExpression.contains(".eval");
    boolean scriptCommandExecute = isScriptEngine(lower(engine)) && looksLikeScriptCommandExecution(expression);
    boolean freemarkerExecute =
        compactExpression.contains("freemarker.template.utility.execute")
            && compactExpression.contains(".exec(");
    return runtimeExec
        || reflectiveRuntimeExec
        || processBuilderStart
        || reflectiveProcessBuilderStart
        || scriptEngineEval
        || freemarkerExecute
        || scriptCommandExecute;
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

  public Optional<Detection> detectGeneratedScriptFileWrite(
      String path, String content, RequestContext request) {
    String normalized = normalizePath(path);
    if (normalized.isBlank() || content == null || content.isBlank() || !request.active()) {
      return Optional.empty();
    }
    if (!generatedScriptPath(normalized) || !GENERATED_SCRIPT_EXEC_PRIMITIVE.matcher(content).find()) {
      return Optional.empty();
    }
    if (!request.hasParameterIn(content) && !request.hasParameterIn(path)) {
      return Optional.empty();
    }
    return Optional.of(
        Detection.log(
            "writeFile",
            "writeFile_generated_script",
            90,
            "Request-controlled generated script contains an interpreter execution primitive",
            request,
            Map.of("path", normalized, "content", abbreviate(content))));
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
          || normalized.contains("springframework.expression")
          || normalized.contains("ognl")
          || normalized.contains("mvel")
          || normalized.contains("templatesimpl")
          || normalized.contains("generatedmethodaccessor")) {
        return true;
      }
    }
    return false;
  }

  private static Optional<String> executableListenerFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      if (frame == null || frame.isBlank()) {
        continue;
      }
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("solr.runexecutablelistener")
          || normalized.endsWith(".runexecutablelistener")
          || normalized.contains("$runexecutablelistener")) {
        return Optional.of(frame);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> configCommandLauncherFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      if (frame == null || frame.isBlank()) {
        continue;
      }
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("org.apache.rocketmq.broker.filtersrv.filterserverutil")
          || normalized.equals("org.apache.rocketmq.broker.filtersrv.filterservermanager")
          || normalized.startsWith("org.apache.rocketmq.broker.filtersrv.filterservermanager$")) {
        return Optional.of(frame);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> configPersistenceFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      if (frame == null || frame.isBlank()) {
        continue;
      }
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("org.apache.rocketmq.remoting.configuration")
          || normalized.equals("org.apache.rocketmq.common.mixall")) {
        return Optional.of(frame);
      }
    }
    return Optional.empty();
  }

  private static boolean unsafeConfigPersistencePath(String normalizedPath) {
    if (normalizedPath == null || normalizedPath.isBlank()) {
      return false;
    }
    String normalized = normalizedPath.replace('\\', '/');
    return normalized.startsWith("/tmp/")
        || normalized.startsWith("/var/tmp/")
        || normalized.startsWith("/dev/shm/")
        || normalized.contains("/../")
        || normalized.contains("/.ssh/")
        || normalized.contains("/cron.")
        || normalized.contains("/cron/")
        || normalized.contains("/systemd/")
        || SCRIPT_FILE.matcher(normalized).matches();
  }

  private static boolean unsafeWebdavDestination(String destination, String destinationPath) {
    return absoluteFilesystemDestination(destination) && unsafeConfigPersistencePath(destinationPath);
  }

  private static boolean webdavMutationMethod(String method) {
    String normalized = lower(method).replaceAll("[^a-z]", "");
    return normalized.equals("move") || normalized.equals("copy");
  }

  private static boolean absoluteFilesystemDestination(String destination) {
    String decoded = percentDecode(destination == null ? "" : destination).trim().replace('\\', '/');
    String normalized = lower(decoded);
    return normalized.startsWith("file:")
        || decoded.startsWith("/")
        || (decoded.length() > 2
            && Character.isLetter(decoded.charAt(0))
            && decoded.charAt(1) == ':'
            && decoded.charAt(2) == '/');
  }

  private static String webdavDestinationPath(String destination) {
    String decoded = percentDecode(destination == null ? "" : destination).trim().replace('\\', '/');
    if (decoded.isBlank()) {
      return "";
    }
    try {
      URI uri = URI.create(decoded);
      if (lower(uri.getScheme()).equals("file")) {
        String path = uri.getPath();
        if (path != null && !path.isBlank()) {
          return normalizePath(path);
        }
      }
    } catch (RuntimeException ignored) {
      // Fall through to plain filesystem-path normalization.
    }
    return normalizePath(decoded);
  }

  private static boolean generatedScriptPath(String normalizedPath) {
    if (normalizedPath == null || normalizedPath.isBlank()) {
      return false;
    }
    String normalized = normalizedPath.replace('\\', '/');
    return normalized.startsWith("/tmp/")
        || normalized.startsWith("/var/tmp/")
        || normalized.startsWith("/dev/shm/")
        || normalized.contains("/cache/")
        || GENERATED_SCRIPT_EXTENSION.matcher(normalized).matches();
  }

  private static String expressionEngineFromStack(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return "";
    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame);
      if (normalized.contains("springframework.expression") || normalized.contains("spel")) {
        return "spel";
      }
      if (normalized.contains("velocity") || normalized.contains("freemarker")) {
        return "template";
      }
      if (normalized.contains("javascript")
          || normalized.contains("nashorn")
          || normalized.contains("rhino")) {
        return "javascript";
      }
      if (normalized.contains("xpath") || normalized.contains("jxpath")) {
        return "xpath";
      }
      if (normalized.contains("jexl")) {
        return "jexl";
      }
      if (normalized.contains("javax.el")
          || normalized.contains("jakarta.el")
          || normalized.contains("org.apache.el")) {
        return "el";
      }
      if (normalized.contains("groovy")
          || normalized.contains("gremlin")
          || normalized.contains("scriptsecurity.sandbox.groovy")) {
        return "groovy";
      }
      if (normalized.contains("javax.script") || normalized.contains("scriptengine")) {
        return "script";
      }
      if (normalized.contains("ognl")) {
        return "ognl";
      }
      if (normalized.contains("mvel")) {
        return "mvel";
      }
    }
    return "";
  }

  private static String expressionRuntimeAlgorithm(String engine) {
    return switch (engine) {
      case "spel" -> "spel_runtime";
      case "template" -> "template_runtime";
      case "javascript" -> "javascript_runtime";
      case "xpath" -> "xpath_runtime";
      case "jexl" -> "jexl_runtime";
      case "el" -> "el_runtime";
      case "mvel", "groovy", "script" -> "script_runtime";
      default -> engine + "_runtime";
    };
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

  private static boolean h2DangerousSql(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    return H2_REMOTE_RUNSCRIPT.matcher(value).find()
        || (H2_CODE_CONTAINER.matcher(value).find() && H2_CODE_PRIMITIVE.matcher(value).find());
  }

  private static boolean mysqlJdbcDeserializationUrl(String url, RequestContext request) {
    if (!request.active() || !request.hasParameterIn(url)) {
      return false;
    }
    String normalized = lower(url);
    if (!normalized.startsWith("jdbc:mysql:") && !normalized.startsWith("jdbc:mariadb:")) {
      return false;
    }
    return MYSQL_JDBC_AUTO_DESERIALIZE.matcher(url).find()
        && MYSQL_JDBC_DESERIALIZATION_TRIGGER.matcher(url).find();
  }

  private static String mysqlJdbcDriver(String normalizedUrl) {
    return normalizedUrl.startsWith("jdbc:mariadb:") ? "mariadb" : "mysql";
  }

  private static boolean looksLikeJavaBeanPollution(String parameterName) {
    if (parameterName == null || parameterName.isBlank()) {
      return false;
    }
    String normalized = normalizeBindingPath(parameterName);
    boolean reachesClassLoader =
        normalized.contains("class.module.classloader")
            || normalized.contains("class.classloader")
            || normalized.startsWith("classloader.")
            || normalized.contains(".classloader.");
    if (!reachesClassLoader) {
      return false;
    }
    for (String target : BEAN_POLLUTION_TARGETS) {
      if (normalized.contains(target)) {
        return true;
      }
    }
    return normalized.contains("pipeline.first.")
        && (normalized.endsWith(".pattern")
            || normalized.endsWith(".suffix")
            || normalized.endsWith(".directory")
            || normalized.endsWith(".prefix")
            || normalized.endsWith(".filedateformat"));
  }

  private static RequestContext redactJavaBeanPollutionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request.parameters().forEach(
        (name, values) -> {
          if (!looksLikeJavaBeanPollution(name)) {
            parameters.put(name, values);
            return;
          }
          var redactedValues = new ArrayList<String>();
          for (int i = 0; i < values.size(); i++) {
            redactedValues.add("[redacted]");
          }
          parameters.put(name, List.copyOf(redactedValues));
        });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactJavaBeanPollutionQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactJavaBeanPollutionQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String rawName = separator >= 0 ? parts[i].substring(0, separator) : parts[i];
      if (looksLikeJavaBeanPollution(percentDecode(rawName))) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<SetupStateResetMatch> setupStateReset(RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    boolean setupContext = setupStateControlPath(request.uri());
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalized = normalizeBindingPath(entry.getKey());
      if (!looksLikeSetupCompletionBinding(normalized, setupContext)) {
        continue;
      }
      Optional<String> resetValue = setupResetValue(entry.getValue());
      if (resetValue.isPresent()) {
        return Optional.of(new SetupStateResetMatch(entry.getKey(), resetValue.orElseThrow()));
      }
    }
    return Optional.empty();
  }

  private static boolean looksLikeSetupCompletionBinding(
      String normalizedParameterName, boolean setupContext) {
    if (!normalizedParameterName.equals("setupcomplete")
        && !normalizedParameterName.endsWith(".setupcomplete")) {
      return false;
    }
    boolean setupBindingChain =
        normalizedParameterName.contains("bootstrap")
            || normalizedParameterName.contains("statusprovider")
            || normalizedParameterName.contains("applicationconfig");
    return setupBindingChain || setupContext;
  }

  private static boolean setupStateControlPath(String uri) {
    String path = uri == null ? "" : uri.split("\\?", 2)[0];
    return SETUP_STATE_CONTROL_PATH.matcher(path).find();
  }

  private static Optional<String> setupResetValue(List<String> values) {
    for (String value : values == null ? List.<String>of() : values) {
      String normalized = lower(percentDecode(value)).trim();
      if (normalized.equals("false")
          || normalized.equals("0")
          || normalized.equals("off")
          || normalized.equals("no")) {
        return Optional.of(normalized);
      }
    }
    return Optional.empty();
  }

  private static String normalizeBindingPath(String parameterName) {
    String normalized =
        percentDecode(parameterName == null ? "" : parameterName)
            .toLowerCase(Locale.ROOT)
            .replace('[', '.')
            .replace(']', '.')
            .replace('/', '.')
            .replace('\\', '.');
    while (normalized.contains("..")) {
      normalized = normalized.replace("..", ".");
    }
    while (normalized.startsWith(".")) {
      normalized = normalized.substring(1);
    }
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private static Optional<ServerSideScriptPutMatch> serverSideScriptPut(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!method.equals("put")) {
      return Optional.empty();
    }
    String rawPath = request.uri() == null ? "" : request.uri().split("\\?", 2)[0];
    for (String variant : pathVariants(rawPath)) {
      String normalized = variant.replace('\\', '/').toLowerCase(Locale.ROOT);
      if (SCRIPT_FILE_REQUEST_PATH.matcher(normalized).matches()) {
        return Optional.of(new ServerSideScriptPutMatch(normalized));
      }
    }
    return Optional.empty();
  }

  private static Optional<UploadFilenameOverrideMatch> uploadFilenameOverride(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    if (!multipartUploadBindingContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!uploadFilenameOverrideParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> targetType = uploadFilenameOverrideTarget(value);
        if (targetType.isPresent()) {
          return Optional.of(
              new UploadFilenameOverrideMatch(
                  entry.getKey(), targetType.orElseThrow(), value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean multipartUploadBindingContext(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!Set.of("post", "put", "patch").contains(method)) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.contains("multipart/form-data");
  }

  private static boolean uploadFilenameOverrideParameter(String parameterName) {
    if (parameterName == null || parameterName.isBlank()) {
      return false;
    }
    String normalized = normalizeBindingPath(parameterName).replace("_", "").replace("-", "");
    return normalized.equals("filename")
        || normalized.endsWith(".filename")
        || normalized.endsWith("filename");
  }

  private static Optional<String> uploadFilenameOverrideTarget(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      String normalized = variant.trim().replace('\\', '/');
      if (normalized.isBlank()) {
        continue;
      }
      if (normalized.indexOf('\0') >= 0 || containsParentSegment(normalized)) {
        return Optional.of("traversal");
      }
      if (normalized.startsWith("/")
          || normalized.startsWith("//")
          || WINDOWS_ABSOLUTE_PATH.matcher(normalized).matches()) {
        return Optional.of("absolute");
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactUploadFilenameOverrideRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    uploadFilenameOverrideParameter(name)
                            && uploadFilenameOverrideTarget(value).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactUploadFilenameOverrideQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactUploadFilenameOverrideQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String rawName = parts[i].substring(0, separator);
      String name = percentDecode(rawName);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (uploadFilenameOverrideParameter(name)
          && uploadFilenameOverrideTarget(value).isPresent()) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean looksLikeInternalIdentityBypass(
      String userAgent, RequestContext request) {
    if (userAgent == null || userAgent.isBlank() || request == null) {
      return false;
    }
    String normalizedAgent = userAgent.trim().toLowerCase(Locale.ROOT);
    boolean internalIdentity =
        INTERNAL_SERVICE_USER_AGENTS.stream()
            .anyMatch(
                agent -> normalizedAgent.equals(agent) || normalizedAgent.startsWith(agent + "/"));
    if (!internalIdentity) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    return SENSITIVE_CONTROL_PATH.matcher(uri).find();
  }

  private record JwtDefaultSecretMatch(String keyId, String algorithm) {}

  private record DefaultEncryptedCookieMatch(String cookieName, String keyId, String cipher) {}

  private record SerializedClientStateMatch(
      String parameter, String encoding, int valueLength, int payloadLength) {}

  private record SerializedClientStatePayload(String encoding, int payloadLength) {}

  private record DefaultCredentialMatch(
      String credentialId, String mechanism, String username, String usernameSource) {}

  private record EmptyCredentialBypassMatch(
      String usernameParameter, String passwordParameter, String bypassParameter) {}

  private record SetupStateResetMatch(String parameter, String value) {}

  private record ServerSideScriptPutMatch(String path) {}

  private record UploadFilenameOverrideMatch(
      String parameter, String targetType, int valueLength) {}

  private record SchedulerShellJobMatch(
      String typeParameter, String typeValue, String sourceParameter, int sourceLength) {}

  private record DebugProcessLaunchMatch(String parameter, int commandLength) {}

  private record DynamicScriptConfigMatch(String parameter, String engine, int sourceLength) {}

  private record DynamicScriptConfigValue(String value, int sourceLength) {}

  private record MessageSelectorExpressionMatch(String engine, int selectorLength) {}

  private record ExpressionHeaderMatch(String header, String engine, int expressionLength) {}

  private record RequestJndiLookupMatch(
      String source, String name, String protocol, int valueLength) {}

  private record TemplateLoaderEnableMatch(
      String source, String parameter, String engine, int sourceLength) {}

  private record TemplateParameterMatch(String parameter, String engine, int sourceLength) {}

  private record TemplateSourceMatch(
      String source, String parameter, String targetType, int valueLength) {}

  private record RequestExpressionParameterMatch(
      String parameter, String engine, int expressionLength) {}

  private record JsonPatchExpressionMatch(String engine, int expressionLength, int bodyLength) {}

  private record OgcFilterSqlInjectionMatch(String parameter, int valueLength) {}

  private record JsonStringField(String name, String value) {}

  private record JsonStringToken(String value, int nextIndex) {}

  private record XmlTextField(String name, String value) {}

  private record RequestExpressionParameterNameMatch(
      String parameter, String engine, int expressionLength) {}

  private record RequestExpressionPathMatch(String engine, int expressionLength) {}

  private record RequestXxePayloadMatch(String parameter, String scheme, int xmlLength) {}

  private record TypedParameterDeserializationMatch(
      String parameter, String className, int valueLength) {}

  private record TypedParameterName(String parameter, String className) {}

  private record TypedPayloadDeserializationMatch(
      String source, String parameter, String className, String trigger, int valueLength) {}

  private record TypedPayloadValue(String className, String trigger) {}

  private record XmlPolymorphicGadgetPayloadMatch(
      String className, String source, int bodyLength) {}

  private record XmlTypeCandidate(String className, String source) {}

  private record RemoteContentStreamMatch(
      String mode, String parameter, String scheme, int sourceLength) {}

  private record RemoteImportScriptWriteMatch(
      String sourceParameter, String targetParameter, String targetType, int remoteSourceCount) {}

  private record RepositoryWebrootWriteMatch(
      String targetParameter, String targetType, String locationType, int valueLength) {}

  private record PlotCommandInjectionMatch(String parameter, int valueLength) {}

  private record SqlSortInjectionMatch(String field, int valueLength) {}

  private record SqlIdentifierInjectionMatch(String field, int valueLength) {}

  private record InternalResourceMatch(String component, String resource, String variant) {}

  private record IncludeAttributeTarget(String type, String resource) {}

  private record JwtTokenSource(String source, String token) {}

  private static boolean jwtVerificationFailureType(String exceptionClass, String message) {
    String normalizedClass = lower(exceptionClass);
    String normalizedMessage = lower(message);
    return normalizedClass.contains("signatureverificationexception")
        || normalizedClass.contains("algorithmmismatchexception")
        || normalizedMessage.contains("signature")
        || normalizedMessage.contains("invalid when verified")
        || normalizedMessage.contains("algorithm");
  }

  private static Optional<JwtTokenSource> jwtTokenSource(RequestContext request) {
    Optional<String> authorization = request.header("authorization").map(String::trim);
    if (authorization.isPresent()
        && authorization.orElseThrow().regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      String token = authorization.orElseThrow().substring("Bearer ".length()).trim();
      if (COMPACT_JWT.matcher(token).matches()) {
        return Optional.of(new JwtTokenSource("authorization", token));
      }
    }
    for (String header : List.of("x-de-token", "x-auth-token", "x-access-token", "x-jwt-token")) {
      String token = request.header(header).orElse("").trim();
      if (COMPACT_JWT.matcher(token).matches()) {
        return Optional.of(new JwtTokenSource(header, token));
      }
    }
    return Optional.empty();
  }

  private static boolean jwtVerificationRequestContext(
      RequestContext request, JwtTokenSource tokenSource) {
    String uri = request.uri();
    if (JWT_VERIFICATION_CONTROL_PATH.matcher(uri).find()) {
      return true;
    }
    return "x-de-token".equals(tokenSource.source()) && lower(uri).contains("/de2api/");
  }

  private static RequestContext redactJwtTokenRequest(RequestContext request, String tokenSource) {
    if (request == null) {
      return RequestContext.empty();
    }
    var headers = new LinkedHashMap<>(request.headers());
    if ("authorization".equals(tokenSource)) {
      headers.put("authorization", "Bearer [redacted]");
    } else if (headers.containsKey(tokenSource)) {
      headers.put(tokenSource, "[redacted]");
    }
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), headers, request.body());
  }

  private static Optional<JwtDefaultSecretMatch> defaultJwtSecretMatch(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String authorization = request.header("authorization").orElse("").trim();
    if (!authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
      return Optional.empty();
    }
    String token = authorization.substring("Bearer ".length()).trim();
    if (token.isBlank() || token.length() > 8192) {
      return Optional.empty();
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
      return Optional.empty();
    }
    String algorithm = jwtHmacAlgorithm(parts[0]).orElse("");
    if (algorithm.isBlank()) {
      return Optional.empty();
    }
    String signingInput = parts[0] + "." + parts[1];
    byte[] signature;
    try {
      signature = Base64.getUrlDecoder().decode(parts[2]);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> secret : DEFAULT_JWT_HMAC_SECRETS.entrySet()) {
      Optional<byte[]> expected = jwtHmac(signingInput, algorithm, secret.getValue());
      if (expected.isPresent() && MessageDigest.isEqual(signature, expected.orElseThrow())) {
        return Optional.of(new JwtDefaultSecretMatch(secret.getKey(), algorithm));
      }
    }
    return Optional.empty();
  }

  private static Optional<DefaultEncryptedCookieMatch> defaultEncryptedCookieMatch(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String cookieHeader = request.header("cookie").orElse("");
    if (cookieHeader.isBlank() || cookieHeader.length() > 8192) {
      return Optional.empty();
    }
    for (String cookie : cookieHeader.split(";")) {
      int separator = cookie.indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = cookie.substring(0, separator).trim();
      String normalizedName = name.toLowerCase(Locale.ROOT);
      if (!DEFAULT_ENCRYPTED_COOKIE_NAMES.contains(normalizedName)) {
        continue;
      }
      String value = percentDecode(cookie.substring(separator + 1).trim());
      if (value.isBlank() || value.length() > 4096) {
        continue;
      }
      Optional<byte[]> encrypted = base64DecodeCookie(value);
      if (encrypted.isEmpty() || encrypted.orElseThrow().length < 32) {
        continue;
      }
      byte[] bytes = encrypted.orElseThrow();
      if ((bytes.length - 16) % 16 != 0) {
        continue;
      }
      for (Map.Entry<String, String> key : DEFAULT_COOKIE_AES_KEYS.entrySet()) {
        Optional<byte[]> plaintext = aesCbcPkcs5Decrypt(bytes, key.getValue());
        if (plaintext.isPresent() && startsWithJavaSerializationStream(plaintext.orElseThrow())) {
          return Optional.of(
              new DefaultEncryptedCookieMatch(name, key.getKey(), "AES/CBC/PKCS5Padding"));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<byte[]> base64DecodeCookie(String value) {
    try {
      return Optional.of(Base64.getDecoder().decode(value));
    } catch (IllegalArgumentException e) {
      try {
        return Optional.of(Base64.getUrlDecoder().decode(value));
      } catch (IllegalArgumentException ignored) {
        return Optional.empty();
      }
    }
  }

  private static Optional<byte[]> aesCbcPkcs5Decrypt(byte[] ivAndCiphertext, String keyBase64) {
    try {
      byte[] key = Base64.getDecoder().decode(keyBase64);
      byte[] iv = new byte[16];
      byte[] ciphertext = new byte[ivAndCiphertext.length - 16];
      System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);
      System.arraycopy(ivAndCiphertext, 16, ciphertext, 0, ciphertext.length);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
      return Optional.of(cipher.doFinal(ciphertext));
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      return Optional.empty();
    }
  }

  private static boolean startsWithJavaSerializationStream(byte[] plaintext) {
    return plaintext.length >= 4
        && (plaintext[0] & 0xff) == 0xac
        && (plaintext[1] & 0xff) == 0xed
        && plaintext[2] == 0
        && plaintext[3] == 5;
  }

  private static Optional<SerializedClientStateMatch> serializedClientState(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isClientStateParameterName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<SerializedClientStatePayload> payload = serializedClientStatePayload(value);
        if (payload.isPresent()) {
          SerializedClientStatePayload match = payload.orElseThrow();
          return Optional.of(
              new SerializedClientStateMatch(
                  entry.getKey(),
                  match.encoding(),
                  value == null ? 0 : value.length(),
                  match.payloadLength()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean isClientStateParameterName(String name) {
    String normalized = normalizeParameterName(name);
    return CLIENT_STATE_PARAMETER_NAMES.contains(normalized) || normalized.endsWith(".viewstate");
  }

  private static Optional<SerializedClientStatePayload> serializedClientStatePayload(
      String value) {
    if (value == null || value.isBlank() || value.length() > 262_144) {
      return Optional.empty();
    }
    Optional<byte[]> decoded = base64DecodeState(percentDecode(value.trim()));
    if (decoded.isEmpty()) {
      return Optional.empty();
    }
    byte[] bytes = decoded.orElseThrow();
    if (startsWithJavaSerializationStream(bytes)) {
      return Optional.of(new SerializedClientStatePayload("base64", bytes.length));
    }
    if (!startsWithGzip(bytes)) {
      return Optional.empty();
    }
    Optional<byte[]> decompressed = gunzipBounded(bytes, 262_144);
    if (decompressed.isEmpty()) {
      return Optional.empty();
    }
    byte[] payload = decompressed.orElseThrow();
    if (startsWithJavaSerializationStream(payload)) {
      return Optional.of(new SerializedClientStatePayload("base64+gzip", payload.length));
    }
    return Optional.empty();
  }

  private static Optional<byte[]> base64DecodeState(String value) {
    if (value == null) {
      return Optional.empty();
    }
    String compact = value.replaceAll("\\s+", "");
    if (compact.length() < 8) {
      return Optional.empty();
    }
    int remainder = compact.length() % 4;
    if (remainder > 0) {
      compact = compact + "=".repeat(4 - remainder);
    }
    try {
      return Optional.of(Base64.getDecoder().decode(compact));
    } catch (IllegalArgumentException e) {
      try {
        return Optional.of(Base64.getUrlDecoder().decode(compact));
      } catch (IllegalArgumentException ignored) {
        return Optional.empty();
      }
    }
  }

  private static boolean startsWithGzip(byte[] bytes) {
    return bytes.length >= 2 && (bytes[0] & 0xff) == 0x1f && (bytes[1] & 0xff) == 0x8b;
  }

  private static Optional<byte[]> gunzipBounded(byte[] bytes, int maxBytes) {
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(bytes));
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[512];
      int read;
      while ((read = gzip.read(buffer)) >= 0) {
        if (output.size() + read > maxBytes) {
          return Optional.empty();
        }
        output.write(buffer, 0, read);
      }
      return Optional.of(output.toByteArray());
    } catch (IOException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static RequestContext redactSerializedClientStateRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    isClientStateParameterName(name)
                            && serializedClientStatePayload(value).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactSerializedClientStateQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactSerializedClientStateQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String name = separator < 0 ? parts[i] : parts[i].substring(0, separator);
      if (isClientStateParameterName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<DefaultCredentialMatch> defaultCredentialAttempt(
      RequestContext request) {
    if (request == null || !request.active() || !defaultCredentialControlContext(request)) {
      return Optional.empty();
    }
    Optional<DefaultCredentialMatch> basic = defaultBasicCredential(request);
    if (basic.isPresent()) {
      return basic;
    }
    Optional<Map.Entry<String, String>> username =
        firstNonBlankParameter(request.parameters(), DEFAULT_CREDENTIAL_USERNAME_PARAMETERS);
    Optional<Map.Entry<String, String>> password =
        firstNonBlankParameter(request.parameters(), DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS);
    if (username.isEmpty() || password.isEmpty()) {
      return Optional.empty();
    }
    return defaultCredentialMatch(
        username.orElseThrow().getValue(),
        password.orElseThrow().getValue(),
        "form",
        username.orElseThrow().getKey());
  }

  private static Optional<DefaultCredentialMatch> defaultBasicCredential(RequestContext request) {
    String authorization = request.header("authorization").orElse("").trim();
    if (!authorization.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
      return Optional.empty();
    }
    String encoded = authorization.substring("Basic ".length()).trim();
    if (encoded.isBlank() || encoded.length() > 2048) {
      return Optional.empty();
    }
    String decoded;
    try {
      decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    int separator = decoded.indexOf(':');
    if (separator <= 0) {
      return Optional.empty();
    }
    return defaultCredentialMatch(
        decoded.substring(0, separator), decoded.substring(separator + 1), "basic", "authorization");
  }

  private static Optional<DefaultCredentialMatch> defaultCredentialMatch(
      String username, String password, String mechanism, String usernameSource) {
    if (username == null || password == null) {
      return Optional.empty();
    }
    String normalizedUsername = username.trim().toLowerCase(Locale.ROOT);
    String normalizedPassword = password.trim().toLowerCase(Locale.ROOT);
    if (normalizedUsername.isBlank() || normalizedPassword.isBlank()) {
      return Optional.empty();
    }
    String credentialId = DEFAULT_CREDENTIAL_PAIRS.get(normalizedUsername + "\n" + normalizedPassword);
    if (credentialId == null) {
      return Optional.empty();
    }
    return Optional.of(
        new DefaultCredentialMatch(credentialId, mechanism, normalizedUsername, usernameSource));
  }

  private static boolean defaultCredentialControlContext(RequestContext request) {
    String uri = request.uri() == null ? "" : request.uri();
    return DEFAULT_CREDENTIAL_CONTROL_PATH.matcher(uri).find();
  }

  private static RequestContext redactCredentialRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isCredentialPasswordName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    var headers = new LinkedHashMap<String, String>(request.headers());
    String authorization = headers.getOrDefault("authorization", "");
    if (authorization.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
      headers.put("authorization", "Basic [redacted]");
    }
    return new RequestContext(
        request.method(), request.uri(), redactCredentialQuery(request.query()), parameters, headers);
  }

  private static String redactCredentialQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      if (isCredentialPasswordName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean isCredentialPasswordName(String name) {
    return DEFAULT_CREDENTIAL_PASSWORD_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static Optional<EmptyCredentialBypassMatch> emptyCredentialBypass(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    String uri = request.uri() == null ? "" : request.uri();
    if (!EMPTY_CREDENTIAL_CONTROL_PATH.matcher(uri).find()) {
      return Optional.empty();
    }
    Optional<String> username =
        firstEmptyParameter(request.parameters(), EMPTY_CREDENTIAL_USERNAME_PARAMETERS);
    Optional<String> password =
        firstEmptyParameter(request.parameters(), EMPTY_CREDENTIAL_PASSWORD_PARAMETERS);
    Optional<String> bypass =
        firstPresentParameter(request.parameters(), EMPTY_CREDENTIAL_BYPASS_PARAMETERS);
    if (username.isPresent() && password.isPresent() && bypass.isPresent()) {
      return Optional.of(
          new EmptyCredentialBypassMatch(
              username.orElseThrow(), password.orElseThrow(), bypass.orElseThrow()));
    }
    return Optional.empty();
  }

  private static Optional<String> firstEmptyParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      String normalized = normalizeParameterName(entry.getKey());
      if (!candidateNames.contains(normalized)) {
        continue;
      }
      List<String> values = entry.getValue();
      if (values == null || values.isEmpty() || values.stream().allMatch(DetectorEngine::isBlank)) {
        return Optional.of(entry.getKey());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> firstPresentParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (String name : parameters.keySet()) {
      if (candidateNames.contains(normalizeParameterName(name))) {
        return Optional.of(name);
      }
    }
    return Optional.empty();
  }

  private static String normalizeParameterName(String name) {
    return name == null ? "" : name.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private static Optional<SchedulerShellJobMatch> schedulerShellJobDispatch(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean schedulerPath =
        SCHEDULER_JOB_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    Optional<SchedulerShellJobMatch> parameterMatch =
        schedulerShellJobParameterDispatch(request.parameters(), schedulerPath);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    List<JsonStringField> fields = jsonStringFields(request.body());
    Optional<JsonStringField> type =
        firstJsonFieldValueMatching(
            fields, SCHEDULER_JOB_TYPE_PARAMETERS, DetectorEngine::isShellSchedulerType);
    if (type.isEmpty()) {
      return Optional.empty();
    }
    Optional<JsonStringField> source = firstNonBlankJsonField(fields, SCHEDULER_JOB_SOURCE_PARAMETERS);
    if (source.isEmpty()) {
      return Optional.empty();
    }
    if (!schedulerPath && schedulerContextSignalCount(fields) < 3) {
      return Optional.empty();
    }
    JsonStringField typeField = type.orElseThrow();
    JsonStringField sourceField = source.orElseThrow();
    return Optional.of(
        new SchedulerShellJobMatch(
            jsonBodyParameter(typeField.name()),
            typeField.value(),
            jsonBodyParameter(sourceField.name()),
            sourceField.value().length()));
  }

  private static Optional<SchedulerShellJobMatch> schedulerShellJobParameterDispatch(
      Map<String, List<String>> parameters, boolean schedulerPath) {
    if (parameters == null || parameters.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> type =
        firstParameterValueMatching(
            parameters,
            SCHEDULER_JOB_TYPE_PARAMETERS,
            DetectorEngine::isShellSchedulerType);
    if (type.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> source =
        firstNonBlankParameter(parameters, SCHEDULER_JOB_SOURCE_PARAMETERS);
    if (source.isEmpty()) {
      return Optional.empty();
    }
    if (!schedulerPath && schedulerContextSignalCount(parameters) < 3) {
      return Optional.empty();
    }
    Map.Entry<String, String> typeEntry = type.orElseThrow();
    Map.Entry<String, String> sourceEntry = source.orElseThrow();
    return Optional.of(
        new SchedulerShellJobMatch(
            typeEntry.getKey(),
            typeEntry.getValue(),
            sourceEntry.getKey(),
            sourceEntry.getValue().length()));
  }

  private static Optional<Map.Entry<String, String>> firstParameterValueMatching(
      Map<String, List<String>> parameters,
      Set<String> candidateNames,
      java.util.function.Predicate<String> valuePredicate) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!candidateNames.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && valuePredicate.test(value)) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<JsonStringField> firstJsonFieldValueMatching(
      List<JsonStringField> fields,
      Set<String> candidateNames,
      java.util.function.Predicate<String> valuePredicate) {
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      if (!candidateNames.contains(normalizeParameterName(field.name()))) {
        continue;
      }
      if (field.value() != null && valuePredicate.test(field.value())) {
        return Optional.of(field);
      }
    }
    return Optional.empty();
  }

  private static Optional<JsonStringField> firstNonBlankJsonField(
      List<JsonStringField> fields, Set<String> candidateNames) {
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      if (!candidateNames.contains(normalizeParameterName(field.name()))) {
        continue;
      }
      if (field.value() != null && !field.value().isBlank()) {
        return Optional.of(field);
      }
    }
    return Optional.empty();
  }

  private static Optional<Map.Entry<String, String>> firstNonBlankParameter(
      Map<String, List<String>> parameters, Set<String> candidateNames) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!candidateNames.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean isShellSchedulerType(String value) {
    String normalized = value == null ? "" : value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    return normalized.equals("glueshell")
        || normalized.equals("shell")
        || normalized.equals("bash")
        || normalized.equals("sh")
        || normalized.equals("cmd")
        || normalized.equals("powershell")
        || normalized.equals("pwsh")
        || normalized.equals("shellscript");
  }

  private static int schedulerContextSignalCount(Map<String, List<String>> parameters) {
    int count = 0;
    for (String name : parameters.keySet()) {
      if (SCHEDULER_JOB_CONTEXT_PARAMETERS.contains(normalizeParameterName(name))) {
        count++;
      }
    }
    return count;
  }

  private static int schedulerContextSignalCount(List<JsonStringField> fields) {
    int count = 0;
    var seen = new LinkedHashSet<String>();
    for (JsonStringField field : fields == null ? List.<JsonStringField>of() : fields) {
      String normalized = normalizeParameterName(field.name());
      if (SCHEDULER_JOB_CONTEXT_PARAMETERS.contains(normalized) && seen.add(normalized)) {
        count++;
      }
    }
    return count;
  }

  private static RequestContext redactSchedulerShellJobRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    SCHEDULER_JOB_SOURCE_PARAMETERS.contains(normalizeParameterName(name))
                            && value != null
                            && !value.isBlank()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactSchedulerShellJobQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactSchedulerShellJobQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      if (SCHEDULER_JOB_SOURCE_PARAMETERS.contains(normalizeParameterName(name))) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<DebugProcessLaunchMatch> debugProcessLaunch(RequestContext request) {
    if (request == null || !request.active() || !debugProcessLaunchContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(entry.getKey()))) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          return Optional.of(new DebugProcessLaunchMatch(entry.getKey(), value.length()));
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(field.name()))
            && field.value() != null
            && !field.value().isBlank()) {
          return Optional.of(
              new DebugProcessLaunchMatch("body." + field.name(), field.value().length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean debugProcessLaunchContext(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    if (!Set.of("post", "put", "patch").contains(method)) {
      return false;
    }
    String uri = lower(percentDecode(request.uri() == null ? "" : request.uri())).replace('\\', '/');
    return (uri.contains("/debug/") || uri.endsWith("/debug"))
        && (uri.contains("/process") || uri.contains("/processes"));
  }

  private static RequestContext redactDebugProcessLaunchRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(name))) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactDebugProcessLaunchQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactDebugProcessLaunchQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String rawName = parts[i].substring(0, separator);
      String name = percentDecode(rawName);
      if (DEBUG_PROCESS_LAUNCH_PARAMETERS.contains(normalizeParameterName(name))) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfig(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean controlPath =
        DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    Optional<DynamicScriptConfigMatch> parameterMatch =
        dynamicScriptConfigParameters(request, controlPath);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return dynamicScriptConfigBody(request, controlPath);
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfigParameters(
      RequestContext request, boolean controlPath) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue()) {
        Optional<DynamicScriptConfigValue> dangerousValue =
            dangerousDynamicScriptConfigValue(request, entry.getKey(), value, controlPath);
        if (dangerousValue.isPresent()) {
          DynamicScriptConfigValue inspected = dangerousValue.orElseThrow();
          String engine = dynamicScriptConfigEngine(request.uri(), entry.getKey(), inspected.value());
          return Optional.of(
              new DynamicScriptConfigMatch(
                  entry.getKey(),
                  engine.isBlank() ? "script" : engine,
                  inspected.sourceLength()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<DynamicScriptConfigValue> dangerousDynamicScriptConfigValue(
      RequestContext request, String name, String value, boolean controlPath) {
    String normalizedName = normalizeParameterName(name);
    boolean configParameter = DYNAMIC_SCRIPT_CONFIG_PARAMETERS.contains(normalizedName);
    if (!controlPath && !configParameter) {
      return Optional.empty();
    }
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (DynamicScriptConfigValue inspected : dynamicScriptConfigValues(value)) {
      String engine = dynamicScriptConfigEngine(request.uri(), name, inspected.value());
      if (containsRuntimeExpressionPrimitive(engine, inspected.value())
          || looksLikeScriptCommandExecution(inspected.value())
          || h2JdbcInitConfig(inspected.value())
          || dangerousJavaConfigConstructor(inspected.value())) {
        return Optional.of(inspected);
      }
    }
    return Optional.empty();
  }

  private static List<DynamicScriptConfigValue> dynamicScriptConfigValues(String value) {
    var values = new ArrayList<DynamicScriptConfigValue>();
    values.add(new DynamicScriptConfigValue(value, value.length()));
    String unicodeDecoded = decodeJavaUnicodeEscapes(value);
    if (!unicodeDecoded.equals(value)) {
      values.add(new DynamicScriptConfigValue(unicodeDecoded, unicodeDecoded.length()));
    }
    decodedBase64ConfigValue(value)
        .ifPresent(decoded -> values.add(new DynamicScriptConfigValue(decoded, decoded.length())));
    return List.copyOf(values);
  }

  private static String decodeJavaUnicodeEscapes(String value) {
    if (value == null || !value.contains("\\u")) {
      return value == null ? "" : value;
    }
    return JAVA_UNICODE_ESCAPE
        .matcher(value)
        .replaceAll(match -> decodeJavaChar(match.group(1), match.group()));
  }

  private static String decodeJavaChar(String value, String fallback) {
    try {
      return String.valueOf((char) Integer.parseInt(value, 16));
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  private static Optional<String> decodedBase64ConfigValue(String value) {
    if (value == null) {
      return Optional.empty();
    }
    String compact = value.replaceAll("\\s+", "");
    if (!BASE64_CONFIG_VALUE.matcher(compact).matches()) {
      return Optional.empty();
    }
    Optional<String> decoded = base64DecodeUtf8(compact);
    if (decoded.isEmpty()) {
      return Optional.empty();
    }
    String text = decoded.orElseThrow();
    return lower(text).contains("jdbc:h2:") ? Optional.of(text) : Optional.empty();
  }

  private static Optional<String> base64DecodeUtf8(String value) {
    try {
      return Optional.of(new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8));
    } catch (IllegalArgumentException first) {
      try {
        return Optional.of(
            new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8));
      } catch (IllegalArgumentException second) {
        return Optional.empty();
      }
    }
  }

  private static boolean h2JdbcInitConfig(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    return lower(value).contains("jdbc:h2:")
        && H2_INIT_SETTING.matcher(value).find()
        && h2DangerousSql(value);
  }

  private static boolean dangerousJavaConfigConstructor(String value) {
    for (String variant : decodedVariants(value)) {
      String normalized = lower(variant).replace('/', '.');
      for (String type : PROTOCOL_CONFIG_INSTANTIATION_TYPES) {
        String normalizedType = lower(type);
        int classIndex = normalized.indexOf(normalizedType);
        if (classIndex < 0) {
          continue;
        }
        int openParen = normalized.indexOf('(', classIndex + normalizedType.length());
        if (openParen < 0) {
          continue;
        }
        String arguments = variant.substring(Math.min(openParen + 1, variant.length()));
        var matcher = JAVA_CONFIG_CONSTRUCTOR_ARGUMENT.matcher(arguments);
        while (matcher.find()) {
          if (remoteConfigScheme(matcher.group(1)).isPresent()) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private static Optional<DynamicScriptConfigMatch> dynamicScriptConfigBody(
      RequestContext request, boolean controlPath) {
    if (!dynamicScriptJsonConfigBody(request, controlPath)) {
      return Optional.empty();
    }
    List<JsonStringField> fields = jsonStringFields(request.body());
    String bodyEngine = dynamicScriptBodyEngineSignal(fields);
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      boolean configField = DYNAMIC_SCRIPT_CONFIG_PARAMETERS.contains(normalizedName);
      if (!controlPath && !configField) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = dynamicScriptConfigEngine(request.uri(), field.name(), value);
      if (!bodyEngine.isBlank() && isDynamicScriptSourceField(field.name())) {
        engine = bodyEngine;
      }
      Optional<DynamicScriptConfigValue> dangerousValue =
          dangerousDynamicScriptConfigValue(request, field.name(), value, controlPath);
      if (dangerousValue.isPresent()) {
        DynamicScriptConfigValue inspected = dangerousValue.orElseThrow();
        engine = dynamicScriptConfigEngine(request.uri(), field.name(), inspected.value());
        if (!bodyEngine.isBlank() && isDynamicScriptSourceField(field.name())) {
          engine = bodyEngine;
        }
        return Optional.of(
            new DynamicScriptConfigMatch(
                jsonBodyParameter(field.name()),
                engine.isBlank() ? "script" : engine,
                inspected.sourceLength()));
      }
    }
    return Optional.empty();
  }

  private static boolean dynamicScriptJsonConfigBody(RequestContext request, boolean controlPath) {
    if (jsonConfigBody(request)) {
      return true;
    }
    if (!controlPath || request == null || request.body().isBlank()) {
      return false;
    }
    String method = lower(request.method());
    if (!method.equals("post") && !method.equals("put") && !method.equals("patch")) {
      return false;
    }
    String trimmed = request.body().trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.contains("text") || contentType.contains("x-www-form-urlencoded");
  }

  private static String dynamicScriptBodyEngineSignal(List<JsonStringField> fields) {
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      if (!normalizedName.equals("lang")
          && !normalizedName.equals("language")
          && !normalizedName.endsWith("lang")
          && !normalizedName.endsWith("language")) {
        continue;
      }
      String engine = dynamicScriptLanguageEngineName(field.value());
      if (!engine.isBlank()) {
        return engine;
      }
    }
    return "";
  }

  private static String dynamicScriptLanguageEngineName(String value) {
    String normalized = normalizeParameterName(value);
    if (normalized.equals("mvel")) {
      return "mvel";
    }
    if (normalized.equals("groovy") || normalized.equals("gremlingroovy")) {
      return "groovy";
    }
    if (normalized.equals("javascript") || normalized.equals("js")) {
      return "javascript";
    }
    if (normalized.equals("spel") || normalized.equals("springel")) {
      return "spel";
    }
    if (normalized.equals("ognl")) {
      return "ognl";
    }
    return "";
  }

  private static boolean isDynamicScriptSourceField(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("script")
        || normalized.equals("source")
        || normalized.equals("code")
        || normalized.equals("expression")
        || normalized.endsWith("script")
        || normalized.endsWith("source")
        || normalized.endsWith("code")
        || normalized.endsWith("expression");
  }

  private static RequestContext redactDynamicScriptConfigRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    boolean controlPath =
        DYNAMIC_SCRIPT_CONFIG_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    dangerousDynamicScriptConfigValue(request, name, value, controlPath).isPresent()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactDynamicScriptConfigQuery(request, controlPath),
        parameters,
        request.headers());
  }

  private static String redactDynamicScriptConfigQuery(RequestContext request, boolean controlPath) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String rawName = parts[i].substring(0, separator);
      String name = percentDecode(rawName);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (dangerousDynamicScriptConfigValue(request, name, value, controlPath).isPresent()) {
        parts[i] = rawName + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static String jsonBodyParameter(String name) {
    return "body." + (name == null || name.isBlank() ? "<unnamed>" : name);
  }

  private static boolean jsonConfigBody(RequestContext request) {
    if (request.body().isBlank()) {
      return false;
    }
    String method = lower(request.method());
    if (!method.equals("post") && !method.equals("put") && !method.equals("patch")) {
      return false;
    }
    String trimmed = request.body().trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    return contentType.isBlank() || contentType.contains("json");
  }

  private static Optional<MessageSelectorExpressionMatch> messageSelectorExpression(
      RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    for (String frame : messageSelectorFrames(request)) {
      if (!stompSelectorContext(request, frame)) {
        continue;
      }
      var matcher = STOMP_SELECTOR_HEADER.matcher(frame);
      while (matcher.find()) {
        String selector = matcher.group(1).trim();
        if (selector.isBlank()) {
          continue;
        }
        String engine = messageSelectorEngine(selector);
        if (!engine.isBlank() && dangerousRequestExpressionValue(engine, selector)) {
          return Optional.of(new MessageSelectorExpressionMatch(engine, selector.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static List<String> messageSelectorFrames(RequestContext request) {
    String body = request.body();
    var frames = new ArrayList<String>();
    frames.add(body);
    if (body.trim().startsWith("[")) {
      int index = 0;
      while (index < body.length()) {
        int quote = body.indexOf('"', index);
        if (quote < 0) {
          break;
        }
        Optional<JsonStringToken> token = parseJsonString(body, quote);
        if (token.isEmpty()) {
          index = quote + 1;
          continue;
        }
        frames.add(token.orElseThrow().value());
        index = token.orElseThrow().nextIndex();
      }
    }
    return List.copyOf(frames);
  }

  private static boolean stompSelectorContext(RequestContext request, String frame) {
    if (frame == null || frame.isBlank()) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    boolean messagePath = MESSAGE_SELECTOR_CONTROL_PATH.matcher(uri).find();
    boolean stompFrame =
        STOMP_COMMAND.matcher(frame).find()
            && lower(frame).contains("destination:")
            && lower(frame).contains("selector:");
    return stompFrame && (messagePath || lower(request.header("content-type").orElse("")).contains("json"));
  }

  private static String messageSelectorEngine(String selector) {
    String expressionEngine = requestExpressionParameterEngine(selector);
    if (!expressionEngine.isBlank()) {
      return expressionEngine;
    }
    String normalized = lower(selector);
    if (normalized.contains("t(java.lang.") || normalized.contains("springframework.expression")) {
      return "spel";
    }
    if (normalized.contains("java.lang.runtime") || normalized.contains("processbuilder")) {
      return "expression";
    }
    return "";
  }

  private static String dynamicScriptConfigEngine(String uri, String parameter, String value) {
    String normalizedUri = lower(uri);
    String normalizedParameter = normalizeParameterName(parameter);
    String normalizedValue = lower(value);
    if (normalizedValue.contains("jdbc:h2:")) {
      return "h2";
    }
    if (normalizedValue.contains("filesystemxmlapplicationcontext")
        || normalizedValue.contains("classpathxmlapplicationcontext")
        || normalizedValue.contains("resourcexmlapplicationcontext")) {
      return "spring";
    }
    if (normalizedValue.contains("shellsession")) {
      return "mvel";
    }
    if (normalizedUri.contains("/actuator/gateway")
        || normalizedValue.contains("#{")
        || normalizedValue.contains("t(java.lang.")) {
      return "spel";
    }
    String compactValue = normalizedValue.replaceAll("\\s+", "");
    if (normalizedValue.contains("script::") || normalizedParameter.contains("mvel")) {
      return "mvel";
    }
    if (normalizedUri.contains("groovy")
        || normalizedParameter.contains("groovy")
        || normalizedUri.contains("gremlin")
        || normalizedParameter.equals("gremlin")
        || normalizedValue.contains("gremlin-groovy")) {
      return "groovy";
    }
    if (compactValue.contains("#runtimeclass")
        || (compactValue.contains("#this")
            && compactValue.contains("getdeclaredmethods")
            && compactValue.contains("invoke"))) {
      return "ognl";
    }
    if (normalizedUri.contains("dataimport")
        || normalizedParameter.equals("dataconfig")
        || normalizedParameter.equals("validationrules")
        || normalizedParameter.equals("function")
        || normalizedValue.contains("function")
        || normalizedValue.contains("//javascript")
        || normalizedValue.contains("<script")
        || normalizedValue.contains("transformer=\"script:")) {
      return "javascript";
    }
    if (normalizedUri.contains("_search")
        || normalizedParameter.equals("scriptfields")
        || normalizedParameter.equals("scriptfield")) {
      return "mvel";
    }
    return "script";
  }

  private static Optional<ExpressionHeaderMatch> expressionHeader(RequestContext request) {
    if (request == null || !request.active() || request.headers().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> entry : request.headers().entrySet()) {
      String header = entry.getKey();
      String value = entry.getValue();
      if (!dangerousExpressionHeader(header, value)) {
        continue;
      }
      String engine = expressionHeaderEngine(header, value);
      return Optional.of(new ExpressionHeaderMatch(header, engine, value.length()));
    }
    return Optional.empty();
  }

  private static boolean isExpressionHeaderName(String name) {
    String normalized = normalizeHeaderName(name);
    return EXPRESSION_HEADER_NAMES.contains(normalized)
        || normalized.endsWith("expression")
        || normalized.endsWith("script")
        || normalized.contains("routingexpression");
  }

  private static boolean isParserExpressionHeaderName(String name) {
    return EXPRESSION_PARSER_HEADER_NAMES.contains(normalizeHeaderName(name));
  }

  private static String expressionHeaderEngine(String name, String value) {
    String normalizedName = normalizeHeaderName(name);
    String valueEngine = requestExpressionParameterEngine(value);
    if (!valueEngine.isBlank()) {
      return valueEngine;
    }
    String normalizedValue = lower(percentDecode(value));
    if (normalizedName.contains("spel")
        || normalizedName.contains("springcloudfunction")
        || normalizedValue.contains("t(java.lang.")) {
      return "spel";
    }
    if (normalizedName.contains("jexl")) {
      return "jexl";
    }
    if (normalizedName.contains("ognl")) {
      return "ognl";
    }
    if (normalizedName.contains("el")) {
      return "el";
    }
    if (normalizedName.contains("script")) {
      return "script";
    }
    return "expression";
  }

  private static boolean dangerousExpressionHeader(String name, String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String engine = expressionHeaderEngine(name, value);
    if (isExpressionHeaderName(name)) {
      return containsRuntimeExpressionPrimitive(engine, percentDecode(value))
          || looksLikeScriptCommandExecution(percentDecode(value));
    }
    if (!isParserExpressionHeaderName(name) || engine.isBlank()) {
      return false;
    }
    String decoded = percentDecode(value);
    return dangerousRequestExpressionValue(engine, decoded)
        || dangerousParserHeaderExpression(engine, decoded);
  }

  private static boolean dangerousParserHeaderExpression(String engine, String value) {
    String compact = lower(value).replaceAll("\\s+", "");
    return "ognl".equals(engine)
        && compact.contains("%{")
        && (compact.contains("#context")
            || compact.contains("_memberaccess")
            || compact.contains("@java.lang.")
            || compact.contains("@ognl.")
            || compact.contains("processbuilder")
            || compact.contains("runtime"));
  }

  private static RequestContext redactExpressionHeaderRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var headers = new LinkedHashMap<String, String>();
    request
        .headers()
        .forEach(
            (name, value) -> {
              if (dangerousExpressionHeader(name, value)) {
                headers.put(name, "[redacted]");
                return;
              }
              headers.put(name, value);
            });
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), headers);
  }

  private static String normalizeHeaderName(String name) {
    return name == null ? "" : name.replaceAll("[^A-Za-z0-9.]", "").toLowerCase(Locale.ROOT);
  }

  private static Optional<RequestJndiLookupMatch> requestJndiLookup(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    boolean jndiDriverSelector = requestHasJndiDriverSelector(request);
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String protocol = jndiParameterProtocol(entry.getKey(), value, jndiDriverSelector);
        if (!protocol.isBlank()) {
          return Optional.of(
              new RequestJndiLookupMatch(
                  "parameter", entry.getKey(), protocol, value == null ? 0 : value.length()));
        }
      }
    }
    for (Map.Entry<String, String> entry : request.headers().entrySet()) {
      String protocol = jndiLookupProtocol(entry.getValue());
      if (!protocol.isBlank()) {
        return Optional.of(
            new RequestJndiLookupMatch(
                "header",
                entry.getKey(),
                protocol,
                entry.getValue() == null ? 0 : entry.getValue().length()));
      }
    }
    return Optional.empty();
  }

  private static String jndiLookupProtocol(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    var variants = new ArrayList<String>();
    variants.add(value);
    String decoded = percentDecode(value);
    variants.add(decoded);
    variants.add(percentDecode(decoded));
    variants.add(deobfuscateLog4jLookup(decoded));
    for (String variant : variants) {
      var matcher = REQUEST_JNDI_LOOKUP.matcher(variant);
      while (matcher.find()) {
        String protocol = lower(matcher.group(1));
        if (JNDI_LOOKUP_PROTOCOLS.contains(protocol)) {
          return protocol;
        }
      }
    }
    return "";
  }

  private static String jndiParameterProtocol(
      String name, String value, boolean jndiDriverSelector) {
    String protocol = jndiLookupProtocol(value);
    if (!protocol.isBlank()) {
      return protocol;
    }
    if (jndiDriverSelector && isJndiRemoteUrlParameter(name)) {
      return directJndiUrlProtocol(value);
    }
    return "";
  }

  private static boolean requestHasJndiDriverSelector(RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isJndiDriverParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (isJndiDriverClass(value)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isJndiDriverParameter(String name) {
    return JNDI_DRIVER_PARAMETER_NAMES.contains(normalizeDottedParameterName(name));
  }

  private static boolean isJndiRemoteUrlParameter(String name) {
    return JNDI_REMOTE_URL_PARAMETER_NAMES.contains(normalizeDottedParameterName(name));
  }

  private static String normalizeDottedParameterName(String name) {
    return normalizeParameterName(name).replace(".", "");
  }

  private static boolean isJndiDriverClass(String value) {
    for (String variant : decodedVariants(value)) {
      String normalized = lower(variant).replace('/', '.').trim();
      if (normalized.equals("javax.naming.initialcontext")
          || normalized.equals("javax.naming.ldap.initialldapcontext")
          || normalized.startsWith("com.sun.jndi.")) {
        return true;
      }
    }
    return false;
  }

  private static String directJndiUrlProtocol(String value) {
    for (String variant : decodedVariants(value)) {
      String protocol = protocolOf(stripWrappingQuotes(variant.trim()));
      if (JNDI_LOOKUP_PROTOCOLS.contains(protocol)) {
        return protocol;
      }
    }
    return "";
  }

  private static List<String> decodedVariants(String value) {
    if (value == null || value.isBlank()) {
      return List.of();
    }
    String decoded = percentDecode(value);
    return List.of(value, decoded, percentDecode(decoded));
  }

  private static String stripWrappingQuotes(String value) {
    if (value.length() >= 2) {
      char first = value.charAt(0);
      char last = value.charAt(value.length() - 1);
      if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        return value.substring(1, value.length() - 1).trim();
      }
    }
    return value;
  }

  private static String deobfuscateLog4jLookup(String value) {
    String normalized = lower(value);
    for (int i = 0; i < 3; i++) {
      normalized =
          normalized.replaceAll("\\$\\{\\s*::-\\s*([a-z0-9])\\s*}", "$1");
      normalized =
          normalized.replaceAll("\\$\\{\\s*(?:lower|upper)\\s*:\\s*([a-z0-9])\\s*}", "$1");
      normalized =
          normalized.replaceAll(
              "\\$\\{\\s*env\\s*:[^}:]{1,80}\\s*:-\\s*([a-z0-9])\\s*}", "$1");
    }
    return normalized;
  }

  private static RequestContext redactJndiLookupRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    boolean jndiDriverSelector = requestHasJndiDriverSelector(request);
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    jndiParameterProtocol(name, value, jndiDriverSelector).isBlank()
                        ? value
                        : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    var headers = new LinkedHashMap<String, String>();
    request
        .headers()
        .forEach(
            (name, value) ->
                headers.put(name, jndiLookupProtocol(value).isBlank() ? value : "[redacted]"));
    return new RequestContext(
        request.method(),
        request.uri(),
        redactJndiLookupQuery(request.query(), jndiDriverSelector),
        parameters,
        headers);
  }

  private static String redactJndiLookupQuery(String query, boolean jndiDriverSelector) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      String value = percentDecode(parts[i].substring(separator + 1));
      if (!jndiParameterProtocol(name, value, jndiDriverSelector).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TemplateLoaderEnableMatch> templateLoaderEnable(
      RequestContext request) {
    if (request == null || !request.active() || !isMutatingHttpMethod(request.method())) {
      return Optional.empty();
    }
    if (!TEMPLATE_LOADER_ENABLE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> enabledName = templateParameterLoaderEnableName(value);
        if (enabledName.isEmpty()) {
          continue;
        }
        String engine = templateLoaderEnableEngine(request, value);
        if (!engine.isBlank()) {
          return Optional.of(
              new TemplateLoaderEnableMatch(
                  "parameter", entry.getKey(), engine, value == null ? 0 : value.length()));
        }
      }
    }
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    Optional<String> bodyField = templateParameterLoaderEnableField(request.body());
    if (bodyField.isEmpty()) {
      return Optional.empty();
    }
    String engine = templateLoaderEnableEngine(request, request.body());
    if (engine.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(
        new TemplateLoaderEnableMatch(
            "body", jsonBodyParameter(bodyField.orElseThrow()), engine, request.body().length()));
  }

  private static boolean isMutatingHttpMethod(String method) {
    String normalized = lower(method);
    return normalized.equals("post")
        || normalized.equals("put")
        || normalized.equals("patch")
        || normalized.equals("delete");
  }

  private static Optional<String> templateParameterLoaderEnableName(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      var matcher = TEMPLATE_PARAMETER_LOADER_ENABLE.matcher(variant);
      if (matcher.find()) {
        return Optional.of(matcher.group(1).replaceAll("\\s+", ""));
      }
    }
    return Optional.empty();
  }

  private static Optional<String> templateParameterLoaderEnableField(String body) {
    for (JsonStringField field : jsonStringFields(body)) {
      if (isTemplateParameterLoaderEnableName(field.name()) && truthyConfigValue(field.value())) {
        return Optional.of(field.name());
      }
    }
    return templateParameterLoaderEnableName(body);
  }

  private static boolean isTemplateParameterLoaderEnableName(String name) {
    String normalized = normalizeParameterName(name).replace(".", "");
    return normalized.equals("paramresourceloaderenabled")
        || normalized.equals("paramsresourceloaderenabled")
        || normalized.equals("parameterresourceloaderenabled")
        || normalized.equals("parametersresourceloaderenabled")
        || normalized.equals("requestresourceloaderenabled");
  }

  private static boolean truthyConfigValue(String value) {
    String normalized =
        stripWrappingQuotes(lower(percentDecode(value == null ? "" : value)).trim());
    return normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("on");
  }

  private static String templateLoaderEnableEngine(RequestContext request, String source) {
    String engine = templateEngineSignal(request.parameters());
    if (!engine.isBlank()) {
      return engine;
    }
    if (jsonConfigBody(request)) {
      engine = templateEngineSignal(jsonStringFields(request.body()));
      if (!engine.isBlank()) {
        return engine;
      }
    }
    String inspected =
        lower(
            percentDecode(
                (request.uri() == null ? "" : request.uri())
                    + "\n"
                    + (source == null ? "" : source)));
    if (inspected.contains("velocityresponsewriter")
        || inspected.contains("velocity")
        || inspected.contains("apache.velocity")) {
      return "velocity";
    }
    if (inspected.contains("freemarker") || inspected.contains("ftl")) {
      return "freemarker";
    }
    if (inspected.contains("thymeleaf")) {
      return "thymeleaf";
    }
    if (inspected.contains("template")) {
      return "template";
    }
    return "";
  }

  private static RequestContext redactTemplateLoaderEnableRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    templateParameterLoaderEnableName(value).isPresent()
                            && !templateLoaderEnableEngine(request, value).isBlank()
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateLoaderEnableQuery(request),
        parameters,
        request.headers());
  }

  private static String redactTemplateLoaderEnableQuery(RequestContext request) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = percentDecode(parts[i].substring(separator + 1));
      if (templateParameterLoaderEnableName(value).isPresent()
          && !templateLoaderEnableEngine(request, value).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TemplateParameterMatch> templateParameter(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String uri = request.uri() == null ? "" : request.uri();
    boolean controlPath =
        TEMPLATE_PARAMETER_CONTROL_PATH.matcher(uri).find();
    boolean messageControlPath = TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(uri).find();
    boolean engineSignal = hasTemplateEngineSignal(request.parameters());
    Optional<TemplateParameterMatch> parameterMatch =
        templateParameterParameters(request, controlPath, messageControlPath, engineSignal);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return templateParameterBody(request, controlPath, engineSignal);
  }

  private static Optional<TemplateParameterMatch> templateParameterParameters(
      RequestContext request, boolean controlPath, boolean messageControlPath, boolean engineSignal) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      boolean strongName = isTemplateParameterName(entry.getKey());
      boolean weakMessageName =
          !strongName && messageControlPath && isTemplateMessageParameterName(entry.getKey());
      if (!strongName && !weakMessageName) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = templateParameterEngine(request, entry.getKey(), value);
        boolean strongTemplateContext =
            strongName && (controlPath || engineSignal || !engine.equals("template"));
        if ((strongTemplateContext || weakMessageName)
            && isDangerousTemplateParameterValue(engine, value, weakMessageName)) {
          return Optional.of(new TemplateParameterMatch(entry.getKey(), engine, value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateParameterMatch> templateParameterBody(
      RequestContext request, boolean controlPath, boolean engineSignal) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    boolean bodyEngineSignal = engineSignal || hasTemplateEngineSignal(jsonStringFields(request.body()));
    for (JsonStringField field : jsonStringFields(request.body())) {
      boolean strongField = isTemplateParameterName(field.name());
      if (!strongField && !isWeakTemplateBodyFieldName(field.name())) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = templateParameterEngine(request, field.name(), value);
      if ((controlPath || bodyEngineSignal || strongField)
          && isDangerousTemplateParameterValue(engine, value)) {
        return Optional.of(new TemplateParameterMatch("body." + field.name(), engine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isTemplateParameterName(String name) {
    String normalized = normalizeParameterName(name);
    return TEMPLATE_PARAMETER_NAMES.contains(normalized)
        || normalized.startsWith("v.template.")
        || normalized.endsWith(".template")
        || (normalized.contains("template")
            && (normalized.contains("body")
                || normalized.contains("content")
                || normalized.contains("source")
                || normalized.contains("payload")
                || normalized.contains("custom")))
        || normalized.contains("velocitytemplate")
        || normalized.contains("freemarkertemplate");
  }

  private static boolean isWeakTemplateBodyFieldName(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("sql")
        || normalized.equals("query")
        || normalized.equals("body")
        || normalized.equals("content")
        || normalized.equals("text")
        || normalized.equals("message");
  }

  private static boolean isTemplateMessageParameterName(String name) {
    return TEMPLATE_MESSAGE_PARAMETER_NAMES.contains(normalizeParameterName(name));
  }

  private static String templateParameterEngine(
      RequestContext request, String parameter, String value) {
    String normalizedParameter = normalizeParameterName(parameter);
    String normalizedValue = lower(value);
    String engineSignal =
        templateEngineSignal(request == null ? Map.<String, List<String>>of() : request.parameters());
    if (normalizedParameter.startsWith("v.template")
        || normalizedParameter.contains("velocity")
        || looksLikeVelocityTemplateSyntax(value)
        || engineSignal.equals("velocity")) {
      return "velocity";
    }
    if (normalizedParameter.contains("freemarker")
        || normalizedParameter.contains("ftl")
        || normalizedValue.contains("freemarker.template")
        || engineSignal.equals("freemarker")) {
      return "freemarker";
    }
    if (normalizedParameter.contains("thymeleaf")
        || normalizedValue.contains("org.thymeleaf")
        || engineSignal.equals("thymeleaf")) {
      return "thymeleaf";
    }
    return "template";
  }

  private static boolean isDangerousTemplateParameterValue(String engine, String value) {
    return containsRuntimeExpressionPrimitive(engine, value)
        || looksLikeScriptCommandExecution(value)
        || looksLikeTemplateCommandExecution(engine, value);
  }

  private static boolean isDangerousTemplateParameterValue(
      String engine, String value, boolean weakMessageName) {
    if (!isDangerousTemplateParameterValue(engine, value)) {
      return false;
    }
    return !weakMessageName || looksLikeTemplateRuntimeSyntax(value);
  }

  private static boolean looksLikeTemplateCommandExecution(String engine, String value) {
    String normalizedEngine = lower(engine);
    String normalizedValue = lower(value);
    if (!normalizedEngine.equals("freemarker") && !normalizedValue.contains("freemarker.template")) {
      return false;
    }
    return normalizedValue.contains("freemarker.template.utility.execute")
        || normalizedValue.contains("template.utility.execute");
  }

  private static boolean looksLikeTemplateRuntimeSyntax(String value) {
    String normalized = lower(value);
    String compact = normalized.replaceAll("\\s+", "");
    return looksLikeVelocityTemplateSyntax(value)
        || normalized.contains("freemarker.template")
        || normalized.contains("<#")
        || compact.contains("${")
        || compact.contains("?new()");
  }

  private static boolean looksLikeVelocityTemplateSyntax(String value) {
    String compact = lower(value).replaceAll("\\s+", "");
    return compact.contains("#set(")
        || compact.contains("#if(")
        || compact.contains("#foreach(")
        || compact.contains("$i18n.")
        || compact.contains("$!i18n.")
        || (compact.contains("$") && compact.contains(".getclass().forname("));
  }

  private static boolean hasTemplateEngineSignal(Map<String, List<String>> parameters) {
    return !templateEngineSignal(parameters).isBlank();
  }

  private static boolean hasTemplateEngineSignal(List<JsonStringField> fields) {
    return !templateEngineSignal(fields).isBlank();
  }

  private static String templateEngineSignal(Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      if (!TEMPLATE_ENGINE_PARAMETER_NAMES.contains(normalizedName)
          && !normalizedName.contains("templateengine")) {
        continue;
      }
      for (String value : entry.getValue()) {
        String normalizedValue = lower(value).trim();
        if (TEMPLATE_ENGINE_VALUES.contains(normalizedValue)) {
          return normalizedValue.equals("ftl") ? "freemarker" : normalizedValue;
        }
      }
    }
    return "";
  }

  private static String templateEngineSignal(List<JsonStringField> fields) {
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      if (!TEMPLATE_ENGINE_PARAMETER_NAMES.contains(normalizedName)
          && !normalizedName.contains("templateengine")) {
        continue;
      }
      String normalizedValue = lower(field.value()).trim();
      if (TEMPLATE_ENGINE_VALUES.contains(normalizedValue)) {
        return normalizedValue.equals("ftl") ? "freemarker" : normalizedValue;
      }
    }
    return "";
  }


  private static RequestContext redactTemplateParameterRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    boolean messageControlPath =
        TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              boolean strongName = isTemplateParameterName(name);
              boolean weakMessageName =
                  !strongName && messageControlPath && isTemplateMessageParameterName(name);
              if (!strongName && !weakMessageName) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                String engine = templateParameterEngine(request, name, value);
                redactedValues.add(
                    value != null && isDangerousTemplateParameterValue(engine, value, weakMessageName)
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateParameterQuery(request),
        parameters,
        request.headers());
  }

  private static String redactTemplateParameterQuery(RequestContext request) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    boolean messageControlPath =
        TEMPLATE_PARAMETER_MESSAGE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = percentDecode(parts[i].substring(separator + 1));
      String decodedName = percentDecode(name);
      boolean strongName = isTemplateParameterName(decodedName);
      boolean weakMessageName =
          !strongName && messageControlPath && isTemplateMessageParameterName(decodedName);
      if (!strongName && !weakMessageName) {
        continue;
      }
      String engine = templateParameterEngine(request, decodedName, value);
      if (isDangerousTemplateParameterValue(engine, value, weakMessageName)) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TemplateSourceMatch> templateSource(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!TEMPLATE_SOURCE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return Optional.empty();
    }
    Optional<TemplateSourceMatch> parameterMatch = templateSourceParameters(request);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    return templateSourceBody(request);
  }

  private static Optional<TemplateSourceMatch> templateSourceParameters(RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<TemplateSourceMatch> match = templateSourceParameterValue(entry.getKey(), value);
        if (match.isPresent()) {
          return match;
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateSourceMatch> templateSourceParameterValue(
      String parameter, String value) {
    if (isTemplateSourceName(parameter)) {
      String targetType = templateSourceTargetType(value);
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "parameter", parameter, targetType, value == null ? 0 : value.length()));
      }
    }
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(value)) {
      if (!isTemplateSourceName(field.name())) {
        continue;
      }
      String targetType = templateSourceTargetType(field.value());
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "parameter",
                parameter + "." + field.name(),
                targetType,
                field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<TemplateSourceMatch> templateSourceBody(RequestContext request) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (!isTemplateSourceName(field.name())) {
        continue;
      }
      String targetType = templateSourceTargetType(field.value());
      if (!targetType.isBlank()) {
        return Optional.of(
            new TemplateSourceMatch(
                "body", "body." + field.name(), targetType, field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isTemplateSourceName(String name) {
    String normalized = normalizeParameterName(name);
    return TEMPLATE_SOURCE_PARAMETER_NAMES.contains(normalized)
        || (normalized.contains("decorator") && normalized.contains("location"))
        || (normalized.contains("screen") && normalized.contains("location"))
        || (normalized.contains("template")
            && (normalized.contains("source")
                || normalized.contains("path")
                || normalized.contains("file")
                || normalized.contains("url")));
  }

  private static String templateSourceTargetType(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String inspected = percentDecode(value.trim());
    URI uri;
    try {
      uri = URI.create(inspected);
    } catch (IllegalArgumentException e) {
      uri = null;
    }
    String scheme = uri == null ? "" : lower(uri.getScheme());
    if (Set.of("http", "https", "ftp", "ldap", "rmi").contains(scheme)) {
      return "remote-url";
    }
    if (Set.of("file", "jar", "netdoc").contains(scheme)) {
      return "local-url";
    }
    for (String variant : pathVariants(inspected)) {
      String normalized = normalizeTemplateSourcePath(variant);
      if (normalized.isBlank()) {
        continue;
      }
      if (pathHasTraversal(normalized)) {
        return "path-traversal";
      }
      if (protectedWebappResource(normalized).isPresent()) {
        return "protected-resource";
      }
      if (TEMPLATE_SOURCE_SENSITIVE_PATH.matcher(normalized).find()) {
        return "sensitive-file";
      }
    }
    return "";
  }

  private static String normalizeTemplateSourcePath(String value) {
    String normalized = value == null ? "" : value.trim().replace('\\', '/').toLowerCase(Locale.ROOT);
    while (normalized.startsWith(". ")) {
      normalized = normalized.substring(1).trim();
    }
    return normalized;
  }

  private static boolean pathHasTraversal(String normalizedPath) {
    return normalizedPath.equals("..")
        || normalizedPath.startsWith("../")
        || normalizedPath.contains("/../")
        || normalizedPath.endsWith("/..");
  }

  private static RequestContext redactTemplateSourceRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isTemplateSourceName(name)
                  || containsTemplateSourceParameterValue(name, values)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTemplateSourceQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTemplateSourceQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (isTemplateSourceName(percentDecode(name))
          || templateSourceParameterValue(percentDecode(name), value).isPresent()) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean containsTemplateSourceParameterValue(String name, List<String> values) {
    for (String value : values == null ? List.<String>of() : values) {
      if (templateSourceParameterValue(name, value).isPresent()) {
        return true;
      }
    }
    return false;
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionParameter(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    Optional<RequestExpressionParameterMatch> parameterMatch =
        requestExpressionParameterValues(request);
    if (parameterMatch.isPresent()) {
      return parameterMatch;
    }
    Optional<RequestExpressionParameterMatch> delegatedParameterMatch =
        requestDelegatedExpressionParameterValues(request);
    if (delegatedParameterMatch.isPresent()) {
      return delegatedParameterMatch;
    }
    Optional<RequestExpressionParameterMatch> bodyMatch = requestExpressionBodyValues(request);
    if (bodyMatch.isPresent()) {
      return bodyMatch;
    }
    return requestExpressionXmlBodyValues(request);
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionParameterValues(
      RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = requestExpressionParameterEngine(value);
        if (!engine.isBlank()
            && isRequestExpressionParameterContext(request, entry.getKey(), engine)
            && dangerousRequestExpressionValue(engine, value)) {
          return Optional.of(
              new RequestExpressionParameterMatch(entry.getKey(), engine, value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<RequestExpressionParameterMatch> requestDelegatedExpressionParameterValues(
      RequestContext request) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value == null || value.isBlank()) {
          continue;
        }
        String engine = requestExpressionParameterEngine(value);
        if (!"ognl".equals(engine)) {
          continue;
        }
        Optional<String> delegatedTargetName = delegatedOgnlParameterName(value);
        if (delegatedTargetName.isEmpty()) {
          continue;
        }
        String targetName = delegatedTargetName.orElseThrow();
        if (!hasDangerousDelegatedExpressionTarget(request, targetName)) {
          continue;
        }
        return Optional.of(
            new RequestExpressionParameterMatch(entry.getKey(), engine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionBodyValues(
      RequestContext request) {
    if (!jsonConfigBody(request)) {
      return Optional.empty();
    }
    boolean controlPath =
        EXPRESSION_BODY_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find();
    List<JsonStringField> fields = jsonStringFields(request.body());
    for (JsonStringField field : fields) {
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      String engine = requestExpressionParameterEngine(value);
      if (!engine.isBlank()
          && isRequestExpressionBodyContext(request, field.name(), engine, controlPath)
          && dangerousRequestExpressionValue(engine, value)) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), engine, value.length()));
      }
    }
    if (!controlPath) {
      return Optional.empty();
    }
    String bodyEngine = requestExpressionBodyEngineSignal(fields);
    if (bodyEngine.isBlank()) {
      return Optional.empty();
    }
    for (JsonStringField field : fields) {
      if (!isExpressionBodyRuntimeValueField(field.name())) {
        continue;
      }
      String value = field.value();
      if (value == null || value.isBlank()) {
        continue;
      }
      if (dangerousRequestExpressionValue(bodyEngine, value)) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), bodyEngine, value.length()));
      }
    }
    return Optional.empty();
  }

  private static boolean isRequestExpressionBodyContext(
      RequestContext request, String name, String engine, boolean controlPath) {
    if ("xpath".equals(engine)) {
      return isRequestExpressionParameterContext(request, name, engine);
    }
    return controlPath || isRequestExpressionParameterContext(request, name, engine);
  }

  private static String requestExpressionBodyEngineSignal(List<JsonStringField> fields) {
    String fallback = "";
    boolean typeProperty = false;
    String valueEngine = "";
    for (JsonStringField field : fields) {
      String normalizedName = normalizeParameterName(field.name());
      String normalizedValue = normalizeParameterName(field.value());
      if (normalizedName.equals("type")
          || normalizedName.equals("engine")
          || normalizedName.endsWith("type")
          || normalizedName.endsWith("engine")) {
        String engine = expressionEngineName(normalizedValue);
        if (!engine.isBlank()) {
          return engine;
        }
      }
      if ((normalizedName.equals("property")
              || normalizedName.equals("name")
              || normalizedName.equals("field"))
          && (normalizedValue.equals("type") || normalizedValue.equals("engine"))) {
        typeProperty = true;
      }
      if (normalizedName.equals("value")) {
        String engine = expressionEngineName(normalizedValue);
        if (!engine.isBlank()) {
          valueEngine = engine;
        }
      }
      if ((normalizedName.equals("property")
              || normalizedName.equals("name")
              || normalizedName.equals("field"))
          && isExpressionBodyRuntimeValueField(normalizedValue)) {
        fallback = "expression";
      }
    }
    if (typeProperty && !valueEngine.isBlank()) {
      return valueEngine;
    }
    return fallback;
  }

  private static String expressionEngineName(String value) {
    String normalized = normalizeParameterName(value);
    if (normalized.equals("jexl") || normalized.equals("commonsjexl")) {
      return "jexl";
    }
    if (normalized.equals("el") || normalized.equals("javaxel") || normalized.equals("jakartael")) {
      return "el";
    }
    if (normalized.equals("spel") || normalized.equals("springel")) {
      return "spel";
    }
    if (normalized.equals("ognl")) {
      return "ognl";
    }
    if (normalized.equals("expression") || normalized.equals("script")) {
      return "expression";
    }
    return "";
  }

  private static boolean isExpressionBodyRuntimeValueField(String name) {
    String normalized = normalizeParameterName(name);
    return REQUEST_EXPRESSION_PARAMETER_NAMES.contains(normalized)
        || normalized.equals("value")
        || normalized.equals("payload")
        || normalized.endsWith("value")
        || normalized.endsWith("expression")
        || normalized.endsWith("script");
  }

  private static Optional<RequestExpressionParameterMatch> requestExpressionXmlBodyValues(
      RequestContext request) {
    if (!xmlRequestBody(request) || !ogcXPathRequestContext(request)) {
      return Optional.empty();
    }
    for (XmlTextField field : xmlTextFields(request.body())) {
      String engine = requestExpressionParameterEngine(field.value());
      if (!engine.isBlank()
          && isRequestExpressionParameterContext(request, field.name(), engine)
          && dangerousRequestExpressionValue(engine, field.value())) {
        return Optional.of(
            new RequestExpressionParameterMatch(
                "body." + field.name(), engine, field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static Optional<String> delegatedOgnlParameterName(String value) {
    String decoded = percentDecode(value);
    var dotMatcher = OGNL_DELEGATED_PARAMETER_DOT.matcher(decoded);
    if (dotMatcher.find()) {
      return Optional.of(dotMatcher.group(1));
    }
    var bracketMatcher = OGNL_DELEGATED_PARAMETER_BRACKET.matcher(decoded);
    if (bracketMatcher.find()) {
      return Optional.of(bracketMatcher.group(1));
    }
    return Optional.empty();
  }

  private static boolean hasDangerousDelegatedExpressionTarget(
      RequestContext request, String targetName) {
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!entry.getKey().equals(targetName)) {
        continue;
      }
      for (String targetValue : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousDelegatedExpressionTargetValue(request, targetName, targetValue)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean dangerousDelegatedExpressionTargetValue(
      RequestContext request, String targetName, String targetValue) {
    if (targetValue == null || targetValue.isBlank()) {
      return false;
    }
    String expressionEngine = requestExpressionParameterEngine(targetValue);
    if (!expressionEngine.isBlank()
        && dangerousRequestExpressionValue(expressionEngine, targetValue)) {
      return true;
    }
    String templateEngine = templateParameterEngine(request, targetName, targetValue);
    return isDangerousTemplateParameterValue(templateEngine, targetValue);
  }

  private static Optional<RequestExpressionParameterNameMatch> requestExpressionParameterName(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (String name : request.parameters().keySet()) {
      String engine = requestExpressionParameterEngine(name);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, name)) {
        return Optional.of(
            new RequestExpressionParameterNameMatch(
                safeExpressionParameterNamePrefix(name), engine, percentDecode(name).length()));
      }
    }
    return Optional.empty();
  }

  private static String requestExpressionParameterEngine(String value) {
    String normalized = lower(expressionDecodedValue(value));
    String compact = normalized.replaceAll("\\s+", "");
    if (compact.contains("@java.lang.runtime@")
        || compact.contains("@java.lang.processbuilder@")
        || compact.contains("_memberaccess")
        || compact.contains("xwork.methodaccessor")
        || compact.contains("ognl.")
        || compact.contains("#context")
        || compact.contains("#parameters")
        || compact.contains("%{")) {
      return "ognl";
    }
    if (compact.contains("#{")
        || compact.contains("t(java.lang.")
        || (compact.contains("#this") && compact.contains("java.lang."))
        || springBindingExpressionName(compact)) {
      return "spel";
    }
    if (compact.contains("scriptenginemanager") && compact.contains(".eval")) {
      return "expression";
    }
    boolean escapedEl = escapedElExpression(compact);
    if ((compact.contains("${") || escapedEl) && compact.contains("java.lang.runtime")) {
      return "el";
    }
    if (compact.contains("${") || escapedEl || compact.contains("#{")) {
      return "expression";
    }
    if (xpathRuntimeExpression(compact)) {
      return "xpath";
    }
    return "";
  }

  private static String expressionDecodedValue(String value) {
    String decoded = percentDecode(value);
    decoded = decodeJavaUnicodeEscapes(decoded);
    return decodeUnicodeEscapes(decoded);
  }

  private static boolean xpathRuntimeExpression(String compactValue) {
    if (compactValue == null || compactValue.isBlank()) {
      return false;
    }
    boolean runtimeExec =
        compactValue.contains("java.lang.runtime")
            && compactValue.contains("getruntime")
            && compactValue.contains("exec");
    boolean processBuilderStart =
        compactValue.contains("processbuilder") && compactValue.contains(".start");
    return (runtimeExec || processBuilderStart) && compactValue.contains("(");
  }

  private static boolean escapedElExpression(String compactValue) {
    int marker = compactValue.indexOf("$\\");
    return marker >= 0
        && marker + 3 < compactValue.length()
        && compactValue.charAt(marker + 3) == '{';
  }

  private static boolean springBindingExpressionName(String compactValue) {
    return compactValue.startsWith("_(")
        && (compactValue.contains("newjava.lang.processbuilder")
            || compactValue.contains("java.lang.runtime")
            || compactValue.contains("runtime.getruntime")
            || compactValue.contains("scriptenginemanager"));
  }

  private static boolean isRequestExpressionParameterContext(String name, String engine) {
    return isRequestExpressionParameterContext(null, name, engine);
  }

  private static boolean isRequestExpressionParameterContext(
      RequestContext request, String name, String engine) {
    if ("xpath".equals(engine)) {
      return isOgcXPathExpressionContext(request, name);
    }
    if ("ognl".equals(engine)) {
      return true;
    }
    String normalized = normalizeParameterName(name);
    return REQUEST_EXPRESSION_PARAMETER_NAMES.contains(normalized)
        || normalized.endsWith("expression")
        || normalized.endsWith("script");
  }

  private static boolean isOgcXPathExpressionContext(RequestContext request, String name) {
    String normalizedName = normalizeParameterName(name);
    return OGC_XPATH_EXPRESSION_PARAMETERS.contains(normalizedName)
        && ogcXPathRequestContext(request);
  }

  private static boolean ogcXPathRequestContext(RequestContext request) {
    if (request == null || !request.active()) {
      return false;
    }
    String uri = request.uri() == null ? "" : request.uri();
    if (OGC_XPATH_CONTROL_PATH.matcher(uri).find()) {
      return true;
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String normalizedValue = normalizeParameterName(value);
        if (normalizedName.equals("service") && OGC_XPATH_SERVICES.contains(normalizedValue)) {
          return true;
        }
        if (normalizedName.equals("request") && OGC_XPATH_REQUESTS.contains(normalizedValue)) {
          return true;
        }
      }
    }
    String body = lower(request.body());
    return body.contains("getpropertyvalue")
        || body.contains("valuereference")
        || body.contains("propertyname");
  }

  private static boolean dangerousRequestExpressionValue(String engine, String value) {
    if (engine.isBlank()) {
      return false;
    }
    String decoded = expressionDecodedValue(value);
    return containsRuntimeExpressionPrimitive(engine, decoded)
        || looksLikeScriptCommandExecution(decoded);
  }

  private static Optional<OgcFilterSqlInjectionMatch> ogcFilterSqlInjection(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    if (!ogcXPathRequestContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isOgcFilterSqlParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousOgcFilterSqlValue(value)) {
          return Optional.of(new OgcFilterSqlInjectionMatch(entry.getKey(), value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean isOgcFilterSqlParameter(String name) {
    return OGC_FILTER_SQL_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static boolean dangerousOgcFilterSqlValue(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String decoded = percentDecode(value);
    return OGC_FILTER_SQL_INJECTION_VALUE.matcher(decoded).find();
  }

  private static RequestContext redactOgcFilterSqlInjectionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (!isOgcFilterSqlParameter(name)) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    value != null && dangerousOgcFilterSqlValue(value) ? "[redacted]" : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactOgcFilterSqlInjectionQuery(request.query()),
        parameters,
        request.headers(),
        request.body());
  }

  private static String redactOgcFilterSqlInjectionQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = percentDecode(parts[i].substring(separator + 1));
      if (isOgcFilterSqlParameter(percentDecode(name)) && dangerousOgcFilterSqlValue(value)) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<JsonPatchExpressionMatch> jsonPatchExpression(RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    if (!"patch".equalsIgnoreCase(request.method())) {
      return Optional.empty();
    }
    String contentType = lower(request.header("content-type").orElse(""));
    if (!contentType.contains("application/json-patch+json")) {
      return Optional.empty();
    }
    String body = request.body();
    if (!body.trim().startsWith("[") || !body.contains("\"path\"")) {
      return Optional.empty();
    }
    for (String path : jsonStringFieldValues(body, "path")) {
      String engine = requestExpressionParameterEngine(path);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, path)) {
        return Optional.of(new JsonPatchExpressionMatch(engine, path.length(), body.length()));
      }
    }
    return Optional.empty();
  }

  private static List<String> jsonStringFieldValues(String json, String fieldName) {
    if (json == null || json.isBlank() || fieldName == null || fieldName.isBlank()) {
      return List.of();
    }
    var values = new ArrayList<String>();
    for (JsonStringField field : jsonStringFields(json)) {
      if (fieldName.equals(field.name())) {
        values.add(field.value());
      }
    }
    return values;
  }

  private static List<JsonStringField> jsonStringFields(String json) {
    if (json == null || json.isBlank()) {
      return List.of();
    }
    var fields = new ArrayList<JsonStringField>();
    int index = 0;
    while (index < json.length()) {
      int quote = json.indexOf('"', index);
      if (quote < 0) {
        break;
      }
      Optional<JsonStringToken> key = parseJsonString(json, quote);
      if (key.isEmpty()) {
        index = quote + 1;
        continue;
      }
      JsonStringToken keyToken = key.orElseThrow();
      index = skipWhitespace(json, keyToken.nextIndex());
      if (index >= json.length() || json.charAt(index) != ':') {
        continue;
      }
      index = skipWhitespace(json, index + 1);
      if (index >= json.length()) {
        continue;
      }
      if (json.charAt(index) == '[') {
        int arrayValue = skipWhitespace(json, index + 1);
        if (arrayValue < json.length()
            && (json.charAt(arrayValue) == '"' || json.charAt(arrayValue) == ']')) {
          index = addJsonStringArrayFields(json, index, keyToken.value(), fields);
        } else {
          index = arrayValue;
        }
        continue;
      }
      if (json.charAt(index) != '"') {
        continue;
      }
      Optional<JsonStringToken> value = parseJsonString(json, index);
      if (value.isPresent()) {
        fields.add(new JsonStringField(keyToken.value(), value.orElseThrow().value()));
        index = value.orElseThrow().nextIndex();
      }
    }
    return fields;
  }

  private static boolean xmlRequestBody(RequestContext request) {
    if (request == null || request.body().isBlank() || request.body().length() > 65536) {
      return false;
    }
    String contentType = lower(request.header("content-type").orElse(""));
    String trimmed = request.body().trim();
    return contentType.contains("xml") || trimmed.startsWith("<");
  }

  private static List<XmlTextField> xmlTextFields(String xml) {
    if (xml == null || xml.isBlank() || xml.length() > 65536) {
      return List.of();
    }
    var fields = new ArrayList<XmlTextField>();
    var matcher = OGC_XPATH_XML_TEXT_FIELD.matcher(xml);
    while (matcher.find()) {
      String name = matcher.group(1);
      String value = decodeXmlText(stripCdata(matcher.group(2)).replaceAll("(?is)<[^>]+>", ""));
      fields.add(new XmlTextField(name, value));
    }
    return List.copyOf(fields);
  }

  private static String stripCdata(String value) {
    if (value == null) {
      return "";
    }
    return value.replace("<![CDATA[", "").replace("]]>", "");
  }

  private static String decodeXmlText(String value) {
    String decoded = decodeXmlCharacterReferences(value);
    return decoded
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&");
  }

  private static int addJsonStringArrayFields(
      String json, int arrayIndex, String fieldName, List<JsonStringField> fields) {
    int current = skipWhitespace(json, arrayIndex + 1);
    while (current < json.length() && json.charAt(current) != ']') {
      if (json.charAt(current) != '"') {
        current++;
        continue;
      }
      Optional<JsonStringToken> value = parseJsonString(json, current);
      if (value.isEmpty()) {
        current++;
        continue;
      }
      fields.add(new JsonStringField(fieldName, value.orElseThrow().value()));
      current = skipWhitespace(json, value.orElseThrow().nextIndex());
      if (current < json.length() && json.charAt(current) == ',') {
        current = skipWhitespace(json, current + 1);
      }
    }
    return current < json.length() ? current + 1 : current;
  }

  private static Optional<JsonStringToken> parseJsonString(String json, int quoteIndex) {
    if (json == null
        || quoteIndex < 0
        || quoteIndex >= json.length()
        || json.charAt(quoteIndex) != '"') {
      return Optional.empty();
    }
    var value = new StringBuilder();
    for (int i = quoteIndex + 1; i < json.length(); i++) {
      char ch = json.charAt(i);
      if (ch == '"') {
        return Optional.of(new JsonStringToken(value.toString(), i + 1));
      }
      if (ch != '\\') {
        value.append(ch);
        continue;
      }
      if (++i >= json.length()) {
        return Optional.empty();
      }
      char escaped = json.charAt(i);
      switch (escaped) {
        case '"', '\\', '/' -> value.append(escaped);
        case 'b' -> value.append('\b');
        case 'f' -> value.append('\f');
        case 'n' -> value.append('\n');
        case 'r' -> value.append('\r');
        case 't' -> value.append('\t');
        case 'u' -> {
          if (i + 4 >= json.length()) {
            return Optional.empty();
          }
          int codepoint = 0;
          for (int j = 1; j <= 4; j++) {
            int digit = Character.digit(json.charAt(i + j), 16);
            if (digit < 0) {
              return Optional.empty();
            }
            codepoint = (codepoint << 4) + digit;
          }
          value.append((char) codepoint);
          i += 4;
        }
        default -> value.append(escaped);
      }
    }
    return Optional.empty();
  }

  private static int skipWhitespace(String value, int index) {
    int current = index;
    while (current < value.length() && Character.isWhitespace(value.charAt(current))) {
      current++;
    }
    return current;
  }

  private static RequestContext redactExpressionParameterRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    Set<String> delegatedExpressionParameters = delegatedExpressionParameterNames(request);
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                String engine = requestExpressionParameterEngine(value);
                redactedValues.add(
                    delegatedExpressionParameters.contains(name)
                            || (isRequestExpressionParameterContext(request, name, engine)
                                && dangerousRequestExpressionValue(engine, value))
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactExpressionParameterQuery(request, delegatedExpressionParameters),
        parameters,
        request.headers());
  }

  private static Set<String> delegatedExpressionParameterNames(RequestContext request) {
    if (request == null || request.parameters().isEmpty()) {
      return Set.of();
    }
    var names = new LinkedHashSet<String>();
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (!"ognl".equals(requestExpressionParameterEngine(value))) {
          continue;
        }
        Optional<String> delegatedTargetName = delegatedOgnlParameterName(value);
        if (delegatedTargetName.isEmpty()) {
          continue;
        }
        String targetName = delegatedTargetName.orElseThrow();
        if (!hasDangerousDelegatedExpressionTarget(request, targetName)) {
          continue;
        }
        names.add(entry.getKey());
        names.add(targetName);
      }
    }
    return Set.copyOf(names);
  }

  private static String redactExpressionParameterQuery(
      RequestContext request, Set<String> delegatedExpressionParameters) {
    String query = request.query();
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = percentDecode(parts[i].substring(separator + 1));
      String engine = requestExpressionParameterEngine(value);
      String name = percentDecode(parts[i].substring(0, separator));
      if (delegatedExpressionParameters.contains(name)
          || (isRequestExpressionParameterContext(request, name, engine)
              && dangerousRequestExpressionValue(engine, value))) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static RequestContext redactExpressionParameterNameRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              String engine = requestExpressionParameterEngine(name);
              String safeName =
                  !engine.isBlank() && dangerousRequestExpressionValue(engine, name)
                      ? safeExpressionParameterName(name)
                      : name;
              parameters.put(safeName, values == null ? List.of() : values);
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactExpressionParameterNameQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactExpressionParameterNameQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      String rawName = separator < 0 ? parts[i] : parts[i].substring(0, separator);
      String engine = requestExpressionParameterEngine(rawName);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, rawName)) {
        parts[i] = safeExpressionParameterName(rawName) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static String safeExpressionParameterName(String name) {
    String prefix = safeExpressionParameterNamePrefix(name);
    return prefix.isBlank() ? "[redacted]" : prefix + "[redacted]";
  }

  private static String safeExpressionParameterNamePrefix(String name) {
    String decoded = percentDecode(name);
    if (decoded.startsWith("_(")) {
      return "_";
    }
    int colon = decoded.indexOf(':');
    if (colon > 0) {
      String colonPrefix = decoded.substring(0, colon);
      if (colonPrefix.matches("[A-Za-z0-9_.-]{1,80}")) {
        return colonPrefix;
      }
    }
    int boundary = decoded.length();
    for (String marker : List.of("[", "%{", "#{", "${")) {
      int index = decoded.indexOf(marker);
      if (index >= 0 && index < boundary) {
        boundary = index;
      }
    }
    String prefix = decoded.substring(0, boundary).trim();
    if (prefix.endsWith(":")) {
      String colonPrefix = prefix.substring(0, prefix.length() - 1);
      if (colonPrefix.matches("[A-Za-z0-9_.-]{1,80}")) {
        return colonPrefix;
      }
    }
    return prefix.matches("[A-Za-z0-9_.-]{1,80}") ? prefix : "";
  }

  private static Optional<RequestExpressionPathMatch> requestExpressionPath(
      RequestContext request) {
    if (request == null || !request.active() || request.uri().isBlank()) {
      return Optional.empty();
    }
    for (String variant : pathVariants(request.uri())) {
      String engine = requestExpressionParameterEngine(variant);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, variant)) {
        return Optional.of(new RequestExpressionPathMatch(engine, variant.length()));
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactExpressionPathRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    return new RequestContext(
        request.method(),
        redactExpressionPathUri(request.uri()),
        request.query(),
        request.parameters(),
        request.headers());
  }

  private static String redactExpressionPathUri(String uri) {
    if (uri == null || uri.isBlank()) {
      return uri == null ? "" : uri;
    }
    for (String variant : pathVariants(uri)) {
      String engine = requestExpressionParameterEngine(variant);
      if (!engine.isBlank() && dangerousRequestExpressionValue(engine, variant)) {
        return "/[redacted]";
      }
    }
    return uri;
  }

  private static Optional<RequestXxePayloadMatch> requestXxePayload(RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        String scheme = xxePayloadScheme(value);
        if (!scheme.isBlank()) {
          return Optional.of(
              new RequestXxePayloadMatch(
                  entry.getKey(), scheme, value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static String xxePayloadScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String decoded = decodeXmlCharacterReferences(percentDecode(value));
    var matcher = REQUEST_XXE_EXTERNAL_ENTITY.matcher(decoded);
    while (matcher.find()) {
      String scheme = lower(matcher.group(1));
      if (XXE_EXTERNAL_ENTITY_PROTOCOLS.contains(scheme)) {
        return scheme;
      }
    }
    return "";
  }

  private static String decodeXmlCharacterReferences(String value) {
    if (value == null || value.indexOf('&') < 0) {
      return value == null ? "" : value;
    }
    String decoded = value;
    for (int i = 0; i < 2; i++) {
      decoded =
          Pattern.compile("(?i)&#x([0-9a-f]{1,6});")
              .matcher(decoded)
              .replaceAll(
                  match -> decodeXmlCodePoint(match.group(1), 16, match.group()));
      decoded =
          Pattern.compile("&#([0-9]{1,7});")
              .matcher(decoded)
              .replaceAll(
                  match -> decodeXmlCodePoint(match.group(1), 10, match.group()));
    }
    return decoded;
  }

  private static String decodeXmlCodePoint(String value, int radix, String fallback) {
    try {
      int codePoint = Integer.parseInt(value, radix);
      return Character.isValidCodePoint(codePoint)
          ? new String(Character.toChars(codePoint))
          : fallback;
    } catch (NumberFormatException e) {
      return fallback;
    }
  }

  private static RequestContext redactXxePayloadRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(xxePayloadScheme(value).isBlank() ? value : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactXxePayloadQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactXxePayloadQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = percentDecode(parts[i].substring(separator + 1));
      if (!xxePayloadScheme(value).isBlank()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TypedParameterDeserializationMatch> typedParameterDeserialization(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      Optional<TypedParameterName> typedName = typedParameterName(entry.getKey());
      if (typedName.isEmpty()) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          TypedParameterName match = typedName.orElseThrow();
          return Optional.of(
              new TypedParameterDeserializationMatch(
                  match.parameter(), match.className(), value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<TypedParameterName> typedParameterName(String rawName) {
    if (rawName == null || rawName.isBlank()) {
      return Optional.empty();
    }
    String decoded = percentDecode(rawName).trim();
    int separator = decoded.lastIndexOf(':');
    if (separator <= 0 || separator == decoded.length() - 1) {
      return Optional.empty();
    }
    String parameter = decoded.substring(0, separator).trim();
    String type = decoded.substring(separator + 1).trim();
    if (type.endsWith("[]")) {
      type = type.substring(0, type.length() - 2);
    }
    String normalized = normalizeJavaTypeName(type);
    if (!REQUEST_TYPED_PARAMETER_CLASS.matcher(type).matches()
        && !REQUEST_TYPED_PARAMETER_CLASS.matcher(normalized).matches()) {
      return Optional.empty();
    }
    if (!dangerousPolymorphicType(normalized)) {
      return Optional.empty();
    }
    return Optional.of(new TypedParameterName(parameter, normalized));
  }

  private static RequestContext redactTypedParameterDeserializationRequest(
      RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (typedParameterName(name).isEmpty()) {
                parameters.put(name, values == null ? List.of() : values);
                return;
              }
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(value == null || value.isBlank() ? value : "[redacted]");
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTypedParameterDeserializationQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTypedParameterDeserializationQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      String value = parts[i].substring(separator + 1);
      if (typedParameterName(percentDecode(name)).isPresent() && !percentDecode(value).isBlank()) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<TypedPayloadDeserializationMatch> typedPayloadDeserialization(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<TypedPayloadValue> payload = typedPayloadValue(value);
        if (payload.isPresent()) {
          TypedPayloadValue match = payload.orElseThrow();
          return Optional.of(
              new TypedPayloadDeserializationMatch(
                  "parameter", entry.getKey(), match.className(), match.trigger(), value.length()));
        }
      }
    }
    Optional<TypedPayloadValue> bodyPayload = typedPayloadValue(request.body());
    return bodyPayload.map(
        match ->
            new TypedPayloadDeserializationMatch(
                "body", "body", match.className(), match.trigger(), request.body().length()));
  }

  private static Optional<TypedPayloadValue> typedPayloadValue(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    String inspected = value.length() > 8192 ? value.substring(0, 8192) : value;
    for (String variant : decodedVariants(inspected)) {
      if (!typedPayloadBindingSyntax(variant)) {
        continue;
      }
      Optional<String> className = dangerousTypedPayloadClass(variant);
      if (className.isEmpty()) {
        continue;
      }
      Optional<String> trigger = typedPayloadTrigger(variant);
      if (trigger.isPresent()) {
        return Optional.of(new TypedPayloadValue(className.orElseThrow(), trigger.orElseThrow()));
      }
    }
    return Optional.empty();
  }

  private static boolean typedPayloadBindingSyntax(String value) {
    String normalized = lower(value);
    return normalized.contains("<wddxpacket")
        || normalized.contains("<struct")
        || TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value).find()
        || TYPED_PAYLOAD_JSON_TYPE.matcher(value).find()
        || TYPED_PAYLOAD_YAML_TAG.matcher(value).find()
        || normalized.contains("@type")
        || normalized.contains("!!");
  }

  private static Optional<String> dangerousTypedPayloadClass(String value) {
    var candidates = new ArrayList<String>();
    var attributeMatcher = TYPED_PAYLOAD_CLASS_ATTRIBUTE.matcher(value);
    while (attributeMatcher.find()) {
      candidates.add(attributeMatcher.group(1));
    }
    var jsonMatcher = TYPED_PAYLOAD_JSON_TYPE.matcher(value);
    while (jsonMatcher.find()) {
      candidates.add(jsonMatcher.group(1));
    }
    var yamlMatcher = TYPED_PAYLOAD_YAML_TAG.matcher(value);
    while (yamlMatcher.find()) {
      candidates.add(yamlMatcher.group(1));
    }
    for (String candidate : candidates) {
      Optional<String> className = dangerousTypedPayloadClassCandidate(candidate);
      if (className.isPresent()) {
        return className;
      }
    }
    return Optional.empty();
  }

  private static Optional<String> dangerousTypedPayloadClassCandidate(String rawClassName) {
    if (rawClassName == null || rawClassName.isBlank()) {
      return Optional.empty();
    }
    var candidates = new ArrayList<String>();
    String normalized = normalizeJavaTypeName(rawClassName);
    candidates.add(normalized);
    if (normalized.length() > 2 && normalized.startsWith("x") && normalized.endsWith("x")) {
      candidates.add(normalized.substring(1, normalized.length() - 1));
    }
    for (String candidate : candidates) {
      String className = normalizeJavaTypeName(candidate);
      if (REQUEST_TYPED_PARAMETER_CLASS.matcher(className).matches()
          && dangerousPolymorphicType(className)) {
        return Optional.of(className);
      }
    }
    return Optional.empty();
  }

  private static Optional<XmlPolymorphicGadgetPayloadMatch> xmlPolymorphicGadgetPayload(
      RequestContext request) {
    if (request == null || !request.active() || request.body().isBlank()) {
      return Optional.empty();
    }
    String body = request.body();
    String contentType = lower(request.header("content-type").orElse(""));
    for (String variant : decodedVariants(body)) {
      if (!looksLikeXmlPayload(variant, contentType)) {
        continue;
      }
      XmlPolymorphicGadgetPayloadMatch best = null;
      int bestPriority = Integer.MAX_VALUE;
      for (XmlTypeCandidate candidate : xmlTypeCandidates(variant)) {
        Optional<String> className = dangerousTypedPayloadClassCandidate(candidate.className());
        if (className.isPresent()) {
          String matchedClass = className.orElseThrow();
          int priority = xmlGadgetClassPriority(matchedClass);
          if (priority < bestPriority) {
            bestPriority = priority;
            best =
                new XmlPolymorphicGadgetPayloadMatch(
                    matchedClass, candidate.source(), body.length());
            if (bestPriority == 0) {
              return Optional.of(best);
            }
          }
        }
      }
      if (best != null) {
        return Optional.of(best);
      }
    }
    return Optional.empty();
  }

  private static boolean looksLikeXmlPayload(String value, String contentType) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String trimmed = value.stripLeading();
    if (!trimmed.startsWith("<")) {
      return false;
    }
    return contentType.isBlank()
        || contentType.contains("xml")
        || trimmed.startsWith("<?xml")
        || trimmed.regionMatches(true, 0, "<map", 0, "<map".length())
        || trimmed.regionMatches(true, 0, "<list", 0, "<list".length())
        || trimmed.regionMatches(true, 0, "<set", 0, "<set".length())
        || trimmed.regionMatches(true, 0, "<object", 0, "<object".length());
  }

  private static List<XmlTypeCandidate> xmlTypeCandidates(String xml) {
    if (xml == null || xml.isBlank()) {
      return List.of();
    }
    var candidates = new ArrayList<XmlTypeCandidate>();
    var attributeMatcher = XML_PAYLOAD_CLASS_ATTRIBUTE.matcher(xml);
    while (attributeMatcher.find()) {
      candidates.add(new XmlTypeCandidate(attributeMatcher.group(1), "xml-class-attribute"));
    }
    var elementMatcher = XML_PAYLOAD_CLASS_ELEMENT.matcher(xml);
    while (elementMatcher.find()) {
      candidates.add(new XmlTypeCandidate(elementMatcher.group(1), "xml-class-element"));
    }
    var tagMatcher = XML_PAYLOAD_JAVA_TYPE_TAG.matcher(xml);
    while (tagMatcher.find()) {
      candidates.add(new XmlTypeCandidate(tagMatcher.group(1), "xml-java-tag"));
    }
    return List.copyOf(candidates);
  }

  private static int xmlGadgetClassPriority(String className) {
    if (POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || DESERIALIZATION_BLACKLIST.contains(className)) {
      return 0;
    }
    if (deserializationGadgetType(className)) {
      return 1;
    }
    return 2;
  }

  private static RequestContext redactBodyRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), request.headers());
  }

  private static Optional<String> typedPayloadTrigger(String value) {
    Optional<String> namingScheme = remoteNamingUrlScheme(value);
    if (namingScheme.isPresent()) {
      return Optional.of("jndi:" + namingScheme.orElseThrow());
    }
    String normalized = lower(value);
    if (normalized.contains("hexasciiserializedmap") || normalized.contains("aced0005")) {
      return Optional.of("serialized");
    }
    if (h2JdbcInitConfig(value)) {
      return Optional.of("jdbc-h2-init");
    }
    return Optional.empty();
  }

  private static Optional<String> remoteNamingUrlScheme(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    var matcher = TYPED_PAYLOAD_REMOTE_NAMING_URL.matcher(value);
    while (matcher.find()) {
      String scheme = lower(matcher.group(1));
      if (JNDI_LOOKUP_PROTOCOLS.contains(scheme)) {
        return Optional.of(scheme);
      }
    }
    return Optional.empty();
  }

  private static RequestContext redactTypedPayloadDeserializationRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    typedPayloadValue(value).isPresent() ? "[redacted]" : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactTypedPayloadDeserializationQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactTypedPayloadDeserializationQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String value = parts[i].substring(separator + 1);
      if (typedPayloadValue(percentDecode(value)).isPresent()) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<RemoteContentStreamMatch> remoteContentStream(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    if (!request.parameters().isEmpty()) {
      for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
        if (!REMOTE_CONTENT_STREAM_URL_PARAMETERS.contains(normalizeParameterName(entry.getKey()))) {
          continue;
        }
        for (String value : entry.getValue()) {
          String scheme = unsafeContentStreamScheme(value);
          if (!scheme.isBlank()) {
            return Optional.of(
                new RemoteContentStreamMatch(
                    "stream-url", entry.getKey(), scheme, value == null ? 0 : value.length()));
          }
        }
      }
    }
    boolean controlPath =
        REMOTE_CONTENT_STREAM_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
            .find();
    if (!controlPath) {
      return Optional.empty();
    }
    if (request.body() != null && REMOTE_CONTENT_STREAM_ENABLE.matcher(request.body()).find()) {
      return Optional.of(
          new RemoteContentStreamMatch(
              "enable-config", "body", "remote-streaming", request.body().length()));
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      String normalizedName = normalizeParameterName(entry.getKey());
      boolean configParameter =
          REMOTE_CONTENT_STREAM_CONFIG_PARAMETERS.contains(normalizedName)
              || normalizedName.contains("config")
              || normalizedName.contains("setting");
      if (!configParameter) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (value != null && REMOTE_CONTENT_STREAM_ENABLE.matcher(value).find()) {
          return Optional.of(
              new RemoteContentStreamMatch(
                  "enable-config", entry.getKey(), "remote-streaming", value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static String unsafeContentStreamScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    String inspected = percentDecode(value.trim());
    URI uri;
    try {
      uri = URI.create(inspected);
    } catch (IllegalArgumentException e) {
      return "";
    }
    String scheme = lower(uri.getScheme());
    if (scheme.isBlank()) {
      return "";
    }
    if (SSRF_PROTOCOLS.contains(scheme)) {
      return scheme;
    }
    if ((scheme.equals("http") || scheme.equals("https")) && isInternalHost(lower(uri.getHost()))) {
      return scheme;
    }
    return "";
  }

  private static RequestContext redactRemoteContentStreamRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRemoteContentStreamUrlName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRemoteContentStreamQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRemoteContentStreamQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      if (isRemoteContentStreamUrlName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static boolean isRemoteContentStreamUrlName(String name) {
    return REMOTE_CONTENT_STREAM_URL_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static Optional<RemoteImportScriptWriteMatch> remoteImportScriptWrite(
      RequestContext request) {
    if (request == null || !request.active() || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    List<Map.Entry<String, String>> sources = remoteImportSources(request.parameters());
    if (sources.isEmpty()) {
      return Optional.empty();
    }
    Optional<Map.Entry<String, String>> target = remoteImportScriptTarget(request.parameters());
    if (target.isEmpty()) {
      return Optional.empty();
    }
    if (!remoteImportControlPath(request) && !hasRemoteImportUrlFlag(request.parameters())) {
      return Optional.empty();
    }
    Map.Entry<String, String> targetEntry = target.orElseThrow();
    return Optional.of(
        new RemoteImportScriptWriteMatch(
            sources.get(0).getKey(),
            targetEntry.getKey(),
            scriptTargetType(targetEntry.getValue()),
            sources.size()));
  }

  private static List<Map.Entry<String, String>> remoteImportSources(
      Map<String, List<String>> parameters) {
    var sources = new ArrayList<Map.Entry<String, String>>();
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportSourceName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (!remoteImportSourceScheme(value).isBlank()) {
          sources.add(Map.entry(entry.getKey(), value));
        }
      }
    }
    return sources;
  }

  private static Optional<Map.Entry<String, String>> remoteImportScriptTarget(
      Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportTargetName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        String normalized = normalizePath(value);
        if (SCRIPT_FILE.matcher(normalized).matches()) {
          return Optional.of(Map.entry(entry.getKey(), value));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean remoteImportControlPath(RequestContext request) {
    return REMOTE_IMPORT_SCRIPT_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find();
  }

  private static Optional<RepositoryWebrootWriteMatch> repositoryWebrootWrite(
      RequestContext request) {
    if (request == null || !request.active() || !repositoryWebrootMutatingMethod(request)) {
      return Optional.empty();
    }
    if (!REPOSITORY_WEBROOT_WRITE_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri())
        .find()) {
      return Optional.empty();
    }
    Optional<String> scriptType = repositoryWebrootScriptTargetType(request);
    if (scriptType.isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, String> target : repositoryWebrootLocationTargets(request)) {
      if (repositoryWebDeploymentPath(target.getValue())) {
        return Optional.of(
            new RepositoryWebrootWriteMatch(
                target.getKey(),
                scriptType.orElseThrow(),
                "webroot",
                target.getValue() == null ? 0 : target.getValue().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean repositoryWebrootMutatingMethod(RequestContext request) {
    String method = lower(request.method()).replaceAll("[^a-z]", "");
    return method.equals("put") || method.equals("post") || method.equals("patch");
  }

  private static List<Map.Entry<String, String>> repositoryWebrootLocationTargets(
      RequestContext request) {
    var targets = new ArrayList<Map.Entry<String, String>>();
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isRepositoryLocationName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (value != null && !value.isBlank()) {
          targets.add(Map.entry(entry.getKey(), value));
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        if (isRepositoryLocationName(field.name())
            && field.value() != null
            && !field.value().isBlank()) {
          targets.add(Map.entry("body." + field.name(), field.value()));
        }
      }
    }
    return List.copyOf(targets);
  }

  private static boolean isRepositoryLocationName(String name) {
    String normalized = normalizeParameterName(name);
    return normalized.equals("location")
        || normalized.equals("path")
        || normalized.equals("repositorylocation")
        || normalized.equals("repositorypath")
        || normalized.equals("repopath")
        || normalized.equals("repodir")
        || normalized.equals("basedir")
        || normalized.endsWith("location")
        || normalized.endsWith("path");
  }

  private static Optional<String> repositoryWebrootScriptTargetType(RequestContext request) {
    Optional<String> uriType = scriptFileType(request.uri());
    if (uriType.isPresent()) {
      return uriType;
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      Optional<String> nameType = scriptFileType(entry.getKey());
      if (nameType.isPresent()) {
        return nameType;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        Optional<String> valueType = scriptFileType(value);
        if (valueType.isPresent()) {
          return valueType;
        }
      }
    }
    if (jsonConfigBody(request)) {
      for (JsonStringField field : jsonStringFields(request.body())) {
        Optional<String> valueType = scriptFileType(field.value());
        if (valueType.isPresent()) {
          return valueType;
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<String> scriptFileType(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : decodedVariants(value)) {
      var matcher = SCRIPT_FILE_TOKEN.matcher(normalizePath(variant));
      while (matcher.find()) {
        String target = matcher.group();
        if (SCRIPT_FILE.matcher(normalizePath(target)).matches()) {
          return Optional.of(scriptTargetType(target));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean repositoryWebDeploymentPath(String value) {
    if (value == null || value.isBlank()) {
      return false;
    }
    String normalized = normalizePath(percentDecode(value));
    return normalized.contains("/webapps/")
        || normalized.endsWith("/webapps")
        || normalized.contains("/webroot/")
        || normalized.endsWith("/webroot")
        || normalized.contains("/wwwroot/")
        || normalized.endsWith("/wwwroot")
        || normalized.contains("/htdocs/")
        || normalized.endsWith("/htdocs")
        || normalized.contains("/public_html/")
        || normalized.endsWith("/public_html")
        || normalized.contains("/var/www/")
        || normalized.equals("/var/www")
        || normalized.startsWith("/var/www/")
        || normalized.contains("/srv/www/")
        || normalized.equals("/srv/www")
        || normalized.startsWith("/srv/www/")
        || normalized.contains("/usr/share/nginx/html");
  }

  private static boolean hasRemoteImportUrlFlag(Map<String, List<String>> parameters) {
    for (Map.Entry<String, List<String>> entry : parameters.entrySet()) {
      if (!isRemoteImportUrlFlagName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        if (isTruthy(value)) {
          return true;
        }
      }
    }
    return false;
  }

  private static String remoteImportSourceScheme(String value) {
    if (value == null || value.isBlank()) {
      return "";
    }
    URI uri;
    try {
      uri = URI.create(percentDecode(value.trim()));
    } catch (IllegalArgumentException e) {
      return "";
    }
    String scheme = lower(uri.getScheme());
    return (scheme.equals("http") || scheme.equals("https") || scheme.equals("ftp")) ? scheme : "";
  }

  private static String scriptTargetType(String value) {
    String normalized = normalizePath(value);
    int dot = normalized.lastIndexOf('.');
    if (dot < 0 || dot == normalized.length() - 1) {
      return "script";
    }
    return normalized.substring(dot + 1);
  }

  private static boolean isRemoteImportSourceName(String name) {
    String normalized = normalizeParameterName(name);
    if (isRemoteImportUrlFlagName(name)) {
      return false;
    }
    return REMOTE_IMPORT_SOURCE_PARAMETERS.contains(normalized)
        || normalized.endsWith("location")
        || normalized.endsWith("url")
        || normalized.endsWith("uri");
  }

  private static boolean isRemoteImportTargetName(String name) {
    String normalized = normalizeParameterName(name);
    return REMOTE_IMPORT_TARGET_PARAMETERS.contains(normalized)
        || normalized.contains("save")
        || normalized.contains("target")
        || normalized.contains("destination")
        || normalized.contains("output");
  }

  private static boolean isRemoteImportUrlFlagName(String name) {
    String normalized = normalizeParameterName(name);
    return REMOTE_IMPORT_URL_FLAG_PARAMETERS.contains(normalized) || normalized.endsWith("isurl");
  }

  private static boolean isRemoteImportSensitiveName(String name) {
    return isRemoteImportSourceName(name) || isRemoteImportTargetName(name);
  }

  private static boolean isTruthy(String value) {
    String normalized = lower(value).trim();
    return normalized.equals("true")
        || normalized.equals("1")
        || normalized.equals("yes")
        || normalized.equals("y")
        || normalized.equals("on");
  }

  private static RequestContext redactRemoteImportScriptWriteRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRemoteImportSensitiveName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRemoteImportScriptWriteQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRemoteImportScriptWriteQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      if (isRemoteImportSensitiveName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static RequestContext redactRepositoryWebrootWriteRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              if (isRepositoryLocationName(name)) {
                parameters.put(name, List.of("[redacted]"));
              } else {
                parameters.put(name, values == null ? List.of() : values);
              }
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactRepositoryWebrootWriteQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactRepositoryWebrootWriteQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = parts[i].substring(0, separator);
      if (isRepositoryLocationName(percentDecode(name))) {
        parts[i] = name + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<PlotCommandInjectionMatch> plotCommandInjection(
      RequestContext request) {
    if (request == null
        || !request.active()
        || request.parameters().isEmpty()
        || !plotCommandContext(request)) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!isPlotCommandParameterName(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue() == null ? List.<String>of() : entry.getValue()) {
        if (dangerousPlotCommandValue(value)) {
          return Optional.of(
              new PlotCommandInjectionMatch(entry.getKey(), value == null ? 0 : value.length()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean plotCommandContext(RequestContext request) {
    String uri = request.uri() == null ? "" : request.uri();
    if (!PLOT_COMMAND_CONTROL_PATH.matcher(uri).find()) {
      return false;
    }
    int contextMarkers = 0;
    for (String name : request.parameters().keySet()) {
      if (PLOT_CONTEXT_PARAMETERS.contains(normalizeParameterName(name))) {
        contextMarkers++;
      }
    }
    return contextMarkers >= 2;
  }

  private static boolean isPlotCommandParameterName(String name) {
    return PLOT_COMMAND_PARAMETERS.contains(normalizeParameterName(name));
  }

  private static boolean dangerousPlotCommandValue(String value) {
    if (value == null || value.isBlank() || value.length() > 4096) {
      return false;
    }
    return GENERATED_SCRIPT_EXEC_PRIMITIVE.matcher(percentDecode(value)).find();
  }

  private static RequestContext redactPlotCommandInjectionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    var parameters = new LinkedHashMap<String, List<String>>();
    request
        .parameters()
        .forEach(
            (name, values) -> {
              var redactedValues = new ArrayList<String>();
              for (String value : values == null ? List.<String>of() : values) {
                redactedValues.add(
                    isPlotCommandParameterName(name) && dangerousPlotCommandValue(value)
                        ? "[redacted]"
                        : value);
              }
              parameters.put(name, List.copyOf(redactedValues));
            });
    return new RequestContext(
        request.method(),
        request.uri(),
        redactPlotCommandInjectionQuery(request.query()),
        parameters,
        request.headers());
  }

  private static String redactPlotCommandInjectionQuery(String query) {
    if (query == null || query.isBlank()) {
      return query == null ? "" : query;
    }
    String[] parts = query.split("&", -1);
    for (int i = 0; i < parts.length; i++) {
      int separator = parts[i].indexOf('=');
      if (separator <= 0) {
        continue;
      }
      String name = percentDecode(parts[i].substring(0, separator));
      String value = percentDecode(parts[i].substring(separator + 1));
      if (isPlotCommandParameterName(name) && dangerousPlotCommandValue(value)) {
        parts[i] = parts[i].substring(0, separator) + "=[redacted]";
      }
    }
    return String.join("&", parts);
  }

  private static Optional<SqlSortInjectionMatch> sqlSortInjection(RequestContext request) {
    if (request == null
        || !request.active()
        || !jsonConfigBody(request)
        || !sqlSortContext(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (isSqlSortInjectionField(field.name()) && dangerousSqlSortValue(field.value())) {
        return Optional.of(new SqlSortInjectionMatch(field.name(), field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean sqlSortContext(RequestContext request) {
    if (!SQL_SORT_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return false;
    }
    return SQL_SORT_CONTEXT_BODY.matcher(request.body()).find();
  }

  private static boolean isSqlSortInjectionField(String name) {
    return SQL_SORT_INJECTION_FIELD_NAMES.contains(normalizeParameterName(name));
  }

  private static boolean dangerousSqlSortValue(String value) {
    if (value == null || value.isBlank() || value.length() > 512) {
      return false;
    }
    String decoded = percentDecode(value).trim();
    String normalized = lower(decoded);
    if (normalized.equals("asc")
        || normalized.equals("desc")
        || normalized.equals("ascending")
        || normalized.equals("descending")) {
      return false;
    }
    return SQL_SORT_INJECTION_VALUE.matcher(decoded).find()
        || SQL_POLICY.matcher(decoded).find();
  }

  private static Optional<SqlIdentifierInjectionMatch> sqlIdentifierInjection(
      RequestContext request) {
    if (request == null
        || !request.active()
        || !jsonConfigBody(request)
        || !sqlIdentifierContext(request)) {
      return Optional.empty();
    }
    for (JsonStringField field : jsonStringFields(request.body())) {
      if (isSqlIdentifierInjectionField(field.name())
          && dangerousSqlIdentifierValue(field.value())) {
        return Optional.of(
            new SqlIdentifierInjectionMatch(field.name(), field.value().length()));
      }
    }
    return Optional.empty();
  }

  private static boolean sqlIdentifierContext(RequestContext request) {
    if (!SQL_IDENTIFIER_CONTROL_PATH.matcher(request.uri() == null ? "" : request.uri()).find()) {
      return false;
    }
    String body = request.body();
    boolean graphqlBody =
        body.contains("\"query\"")
            && body.contains("\"variables\"")
            && lower(body).contains("graphql");
    return graphqlBody || SQL_IDENTIFIER_CONTEXT_BODY.matcher(body).find();
  }

  private static boolean isSqlIdentifierInjectionField(String name) {
    return SQL_IDENTIFIER_INJECTION_FIELD_NAMES.contains(normalizeParameterName(name));
  }

  private static boolean dangerousSqlIdentifierValue(String value) {
    if (value == null || value.isBlank() || value.length() > 512) {
      return false;
    }
    String decoded = percentDecode(value).trim();
    if (SAFE_SQL_IDENTIFIER_VALUE.matcher(decoded).matches()) {
      return false;
    }
    return SQL_IDENTIFIER_INJECTION_VALUE.matcher(decoded).find()
        || SQL_POLICY.matcher(decoded).find();
  }

  private static RequestContext redactSqlSortInjectionRequest(RequestContext request) {
    if (request == null) {
      return RequestContext.empty();
    }
    return new RequestContext(
        request.method(), request.uri(), request.query(), request.parameters(), request.headers());
  }

  private static Optional<String> jwtHmacAlgorithm(String headerPart) {
    String header;
    try {
      header = new String(Base64.getUrlDecoder().decode(headerPart), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    var matcher = JWT_HMAC_ALGORITHM.matcher(header);
    if (!matcher.find()) {
      return Optional.empty();
    }
    return Optional.of(matcher.group(1));
  }

  private static Optional<byte[]> jwtHmac(String signingInput, String jwtAlgorithm, String secret) {
    String macAlgorithm =
        switch (jwtAlgorithm) {
          case "HS256" -> "HmacSHA256";
          case "HS384" -> "HmacSHA384";
          case "HS512" -> "HmacSHA512";
          default -> "";
        };
    if (macAlgorithm.isBlank()) {
      return Optional.empty();
    }
    try {
      Mac mac = Mac.getInstance(macAlgorithm);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlgorithm));
      return Optional.of(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
    } catch (RuntimeException | java.security.GeneralSecurityException e) {
      return Optional.empty();
    }
  }

  private static Optional<Map.Entry<String, String>> requestControlledInternalForward(
      RequestContext request) {
    if (request == null || request.parameters().isEmpty()) {
      return Optional.empty();
    }
    for (Map.Entry<String, List<String>> entry : request.parameters().entrySet()) {
      if (!internalForwardParameter(entry.getKey())) {
        continue;
      }
      for (String value : entry.getValue()) {
        Optional<String> target = internalForwardTarget(value);
        if (target.isPresent()) {
          return Optional.of(Map.entry(entry.getKey(), target.orElseThrow()));
        }
      }
    }
    return Optional.empty();
  }

  private static boolean internalForwardParameter(String name) {
    if (name == null || name.isBlank()) {
      return false;
    }
    String normalized =
        name.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "").replace(".", "");
    return INTERNAL_FORWARD_PARAMETERS.contains(normalized);
  }

  private static Optional<String> internalForwardTarget(String value) {
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }
    for (String variant : pathVariants(value.trim())) {
      String normalized = variant.trim().replace('\\', '/');
      if (!normalized.startsWith("/") || !INTERNAL_FORWARD_JSP_SUFFIX.matcher(normalized).find()) {
        continue;
      }
      String path = normalized.split("[?#]", 2)[0];
      String stripped = stripServletPathParameters(path);
      if (INTERNAL_FORWARD_CONTROL_PATH.matcher(stripped).find()) {
        return Optional.of(normalized);
      }
    }
    return Optional.empty();
  }

  private static String stripServletPathParameters(String path) {
    String[] segments = path.split("/", -1);
    StringBuilder builder = new StringBuilder(path.length());
    for (int i = 0; i < segments.length; i++) {
      if (i > 0) {
        builder.append('/');
      }
      String segment = segments[i];
      int semicolon = segment.indexOf(';');
      builder.append(semicolon >= 0 ? segment.substring(0, semicolon) : segment);
    }
    return builder.toString();
  }

  private static Optional<InternalResourceMatch> protectedInternalResourceRequest(
      RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    var candidates = new LinkedHashMap<String, String>();
    addCandidate(candidates, "uri", request.uri());
    if (looksLikeQueryResourceSpec(request.query())) {
      addCandidate(candidates, "query", request.query());
      addCandidate(candidates, "target", request.uri() + "?" + request.query());
    }
    for (Map.Entry<String, String> candidate : candidates.entrySet()) {
      String raw = normalizeRequestTarget(candidate.getValue());
      if (raw.isBlank()) {
        continue;
      }
      Optional<InternalResourceMatch> ambiguous =
          ambiguousProtectedInternalResource(candidate.getKey(), candidate.getValue(), raw);
      if (ambiguous.isPresent()) {
        return ambiguous;
      }
      if (protectedWebappResource(raw).isPresent()) {
        continue;
      }
      for (String variant : pathVariants(candidate.getValue())) {
        String normalized = normalizeRequestTarget(variant);
        if (normalized.equals(raw)) {
          continue;
        }
        Optional<String> resource = protectedWebappResource(normalized);
        if (resource.isPresent()) {
          return Optional.of(
              new InternalResourceMatch(
                  candidate.getKey(), resource.orElseThrow(), decodingVariant(candidate.getValue(), variant)));
        }
      }
    }
    return Optional.empty();
  }

  private static Optional<InternalResourceMatch> ambiguousProtectedInternalResource(
      String component, String value, String raw) {
    var matcher = PROTECTED_WEBAPP_RESOURCE.matcher(raw);
    if (!matcher.find()) {
      return Optional.empty();
    }
    String prefix = raw.substring(0, matcher.start(1));
    if (!ambiguousProtectedResourcePrefix(prefix)) {
      return Optional.empty();
    }
    return Optional.of(
        new InternalResourceMatch(
            component,
            matcher.group(1).toUpperCase(Locale.ROOT),
            protectedResourceAmbiguityVariant(value, prefix)));
  }

  private static boolean ambiguousProtectedResourcePrefix(String prefix) {
    String normalized = lower(prefix);
    if (normalized.contains("%2e") || normalized.contains("%252e") || normalized.contains("%u002e")) {
      return true;
    }
    String decoded = percentDecode(normalized);
    return (normalized.contains("%00") || decoded.indexOf('\0') >= 0)
        && (normalized.contains(".") || decoded.contains("."));
  }

  private static String protectedResourceAmbiguityVariant(String value, String prefix) {
    String normalized = lower(prefix);
    if (normalized.contains("%u002e")) {
      return "unicode-decoded";
    }
    if (normalized.contains("%252e")) {
      return "double-decoded";
    }
    if (normalized.contains("%2e")) {
      return "decoded";
    }
    if (normalized.contains("%00") || percentDecode(value).indexOf('\0') >= 0) {
      return "nul-segment";
    }
    return "ambiguous-path";
  }

  private static void addCandidate(Map<String, String> candidates, String component, String value) {
    if (value != null && !value.isBlank()) {
      candidates.put(component, value);
    }
  }

  private static String normalizeRequestTarget(String value) {
    return value == null ? "" : value.replace('\\', '/').toLowerCase(Locale.ROOT);
  }

  private static Optional<String> protectedWebappResource(String value) {
    var matcher = PROTECTED_WEBAPP_RESOURCE.matcher(value);
    if (!matcher.find()) {
      return Optional.empty();
    }
    return Optional.of(matcher.group(1).toUpperCase(Locale.ROOT));
  }

  private static boolean looksLikeQueryResourceSpec(String query) {
    if (query == null || query.isBlank() || query.contains("=")) {
      return false;
    }
    String trimmed = query.trim();
    return trimmed.startsWith("/") || percentDecode(trimmed).startsWith("/");
  }

  private static String decodingVariant(String raw, String variant) {
    String once = percentDecode(raw);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(once))) {
      return "decoded";
    }
    String twice = percentDecode(once);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(twice))) {
      return "double-decoded";
    }
    String unicode = decodeUnicodeEscapes(once);
    if (normalizeRequestTarget(variant).equals(normalizeRequestTarget(unicode))) {
      return "unicode-decoded";
    }
    return "decoded";
  }

  private static boolean isServletIncludeAttribute(String name) {
    String normalized = lower(name);
    return normalized.startsWith("javax.servlet.include.")
        || normalized.startsWith("jakarta.servlet.include.");
  }

  private static Optional<IncludeAttributeTarget> suspiciousIncludeAttributeTarget(String value) {
    for (String variant : pathVariants(value)) {
      String normalized = normalizePath(variant);
      if (normalized.isBlank()) {
        continue;
      }
      Optional<String> resource = protectedWebappResource(normalized);
      if (resource.isPresent()) {
        return Optional.of(new IncludeAttributeTarget("protected-resource", resource.orElseThrow()));
      }
      if (SCRIPT_FILE.matcher(normalized).matches()) {
        return Optional.of(new IncludeAttributeTarget("server-side-script", extensionOf(normalized)));
      }
      if (hasConfusingDotSegment(normalized)) {
        return Optional.of(new IncludeAttributeTarget("path-traversal", "dot-segment"));
      }
    }
    return Optional.empty();
  }

  private static boolean legitimateServletIncludeStack(List<String> stackClassNames) {
    if (stackClassNames == null || stackClassNames.isEmpty()) {
      return false;
    }
    for (String className : stackClassNames) {
      String normalized = lower(className).replace('/', '.');
      if (normalized.endsWith(".applicationdispatcher")
          || normalized.contains(".applicationdispatcher.")
          || normalized.endsWith(".requestdispatcher")
          || normalized.contains(".requestdispatcher.")) {
        return true;
      }
    }
    return false;
  }

  private static Optional<String> confusingRequestPath(String uri) {
    if (uri == null || uri.isBlank()) {
      return Optional.empty();
    }
    String path = uri.split("\\?", 2)[0];
    boolean sensitiveControlPath = SENSITIVE_CONTROL_PATH.matcher(path).find();
    for (String variant : pathVariants(path)) {
      String normalized = variant.replace('\\', '/');
      if (hasConfusingDotSegment(normalized)
          || (sensitiveControlPath && hasPathControlCharacter(normalized))) {
        return Optional.of(normalized);
      }
      Optional<String> canonicalControlPath = canonicalSensitiveControlPath(normalized);
      if (canonicalControlPath.isPresent()) {
        return canonicalControlPath;
      }
    }
    return Optional.empty();
  }

  private static Optional<String> canonicalSensitiveControlPath(String path) {
    if (path == null || path.isBlank()) {
      return Optional.empty();
    }
    String normalized = stripServletPathParameters(path.replace('\\', '/'));
    if (!hasSingleDotSegment(normalized) && !hasDuplicateSlash(normalized)) {
      return Optional.empty();
    }
    String canonical = collapsePathDotSegments(normalized);
    if (canonical.equals(normalized) || !SENSITIVE_CONTROL_PATH.matcher(canonical).find()) {
      return Optional.empty();
    }
    return Optional.of(canonical);
  }

  private static boolean hasSingleDotSegment(String path) {
    for (String segment : path.split("/", -1)) {
      if (segment.equals(".")) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasDuplicateSlash(String path) {
    return path != null && path.contains("//");
  }

  private static String collapsePathDotSegments(String path) {
    boolean absolute = path.startsWith("/");
    var segments = new ArrayList<String>();
    for (String segment : path.split("/+", -1)) {
      if (segment.isBlank() || segment.equals(".")) {
        continue;
      }
      if (segment.equals("..")) {
        if (!segments.isEmpty()) {
          segments.remove(segments.size() - 1);
        }
        continue;
      }
      segments.add(segment);
    }
    String collapsed = String.join("/", segments);
    if (absolute) {
      collapsed = "/" + collapsed;
    }
    return collapsed.isBlank() ? "/" : collapsed;
  }

  private static List<String> pathVariants(String path) {
    var variants = new ArrayList<String>();
    addVariant(variants, path);
    addOverlongUtf8Variants(variants, path);
    String once = percentDecode(path);
    addVariant(variants, once);
    addVariant(variants, decodeUnicodeEscapes(once));
    addLenientPercentVariants(variants, once);
    addOverlongUtf8Variants(variants, once);
    String twice = percentDecode(once);
    addVariant(variants, twice);
    addVariant(variants, decodeUnicodeEscapes(twice));
    addLenientPercentVariants(variants, twice);
    addOverlongUtf8Variants(variants, twice);
    addLenientPercentVariants(variants, path);
    String ghost = lowByteUnicodeDecode(path);
    if (!ghost.equals(path)) {
      addVariant(variants, ghost);
      addVariant(variants, decodeUnicodeEscapes(ghost));
      addOverlongUtf8Variants(variants, ghost);
      String decodedGhost = percentDecode(ghost);
      addVariant(variants, decodedGhost);
      addVariant(variants, decodeUnicodeEscapes(decodedGhost));
      addLenientPercentVariants(variants, decodedGhost);
      addOverlongUtf8Variants(variants, decodedGhost);
    }
    return variants;
  }

  private static void addOverlongUtf8Variants(List<String> variants, String value) {
    String overlong = overlongUtf8Decode(value);
    if (!overlong.equals(value)) {
      addVariant(variants, overlong);
      addVariant(variants, decodeUnicodeEscapes(overlong));
    }
  }

  private static void addLenientPercentVariants(List<String> variants, String value) {
    String lenient = jettyLenientPercentDecode(value);
    if (!lenient.equals(value)) {
      addVariant(variants, lenient);
      addVariant(variants, decodeUnicodeEscapes(lenient));
    }
  }

  private static void addVariant(List<String> variants, String value) {
    if (value == null || value.isBlank()) {
      return;
    }
    if (!variants.contains(value)) {
      variants.add(value);
    }
  }

  private static boolean isMutatingJmxOperation(String operationName) {
    String normalized = lower(operationName);
    return normalized.startsWith("add")
        || normalized.startsWith("set")
        || normalized.startsWith("create")
        || normalized.startsWith("copy")
        || normalized.startsWith("load")
        || normalized.startsWith("reload")
        || normalized.startsWith("update")
        || normalized.startsWith("write")
        || normalized.startsWith("save")
        || normalized.startsWith("store")
        || normalized.startsWith("dump")
        || normalized.startsWith("install")
        || normalized.startsWith("deploy")
        || normalized.startsWith("import")
        || normalized.startsWith("start");
  }

  private static boolean looksLikeRemoteJmxConfig(String argument) {
    String normalized = lower(argument.trim());
    if (normalized.isBlank() || !containsRemoteProtocol(normalized)) {
      return false;
    }
    return normalized.contains("brokerconfig=")
        || normalized.contains("xbean:")
        || normalized.contains("spring:")
        || (normalized.contains("config") && normalized.contains(".xml"));
  }

  private static Optional<String> jmxScriptWriteTarget(String argument) {
    if (argument == null || argument.isBlank()) {
      return Optional.empty();
    }
    var matcher = SCRIPT_FILE_TOKEN.matcher(argument);
    while (matcher.find()) {
      String target = normalizePath(matcher.group());
      if (SCRIPT_FILE.matcher(target).matches()) {
        return Optional.of(target);
      }
    }
    return Optional.empty();
  }

  private static boolean containsRemoteProtocol(String value) {
    String normalized = lower(value);
    for (String protocol : REMOTE_CONFIG_PROTOCOLS) {
      if (normalized.contains(protocol + "://")) {
        return true;
      }
    }
    return false;
  }

  private static String xmlAttachmentMechanism(String mechanism) {
    String normalized = lower(mechanism).replace('_', '-');
    if (normalized.equals("cxf-aegis-xop") || normalized.equals("cxf-aegis-mtom")) {
      return "cxf-aegis-xop";
    }
    return "";
  }

  private static String attachmentHref(String href) {
    String value = href == null ? "" : href.trim();
    int cid = lower(value).indexOf("cid:");
    if (cid >= 0) {
      value = value.substring(cid + 4).trim();
    }
    return value;
  }

  private static boolean hasConfusingDotSegment(String path) {
    for (String rawSegment : path.split("/+")) {
      if (rawSegment.isBlank()) {
        continue;
      }
      String segment = rawSegment;
      int semicolon = segment.indexOf(';');
      if (semicolon >= 0) {
        segment = segment.substring(0, semicolon);
      }
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasPathControlCharacter(String path) {
    for (int i = 0; i < path.length(); i++) {
      if (Character.isISOControl(path.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static String percentDecode(String value) {
    if (value == null || value.indexOf('%') < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%' && i + 2 < value.length()) {
        int high = Character.digit(value.charAt(i + 1), 16);
        int low = Character.digit(value.charAt(i + 2), 16);
        if (high >= 0 && low >= 0) {
          decoded.append((char) ((high << 4) + low));
          i += 2;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  private static String jettyLenientPercentDecode(String value) {
    if (value == null || value.indexOf('%') < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%' && i + 2 < value.length()) {
        int high = jettyLenientHexDigit(value.charAt(i + 1));
        int low = jettyLenientHexDigit(value.charAt(i + 2));
        if (high >= 0 && low >= 0) {
          decoded.append((char) ((high << 4) + low));
          changed = true;
          i += 2;
          continue;
        }
      }
      decoded.append(ch);
    }
    return changed ? decoded.toString() : value;
  }

  private static int jettyLenientHexDigit(char ch) {
    if (ch > 0x7f) {
      return -1;
    }
    int digit = ((ch & 0x1f) + ((ch >> 6) * 0x19) - 0x10);
    return digit >= 0 && digit <= 15 ? digit : -1;
  }

  private static String overlongUtf8Decode(String value) {
    if (value == null || value.isBlank()) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      int first = encodedByteValue(value, i);
      int firstNext = encodedByteNextIndex(value, i);
      if (first >= 0xc0 && first <= 0xdf && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80) {
          int codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
          if (overlongPathCharacter(codepoint)) {
            decoded.append((char) codepoint);
            i = secondNext - 1;
            changed = true;
            continue;
          }
        }
      }
      if (first == 0xe0 && firstNext < value.length()) {
        int second = encodedByteValue(value, firstNext);
        int secondNext = encodedByteNextIndex(value, firstNext);
        if ((second & 0xc0) == 0x80 && secondNext < value.length()) {
          int third = encodedByteValue(value, secondNext);
          int thirdNext = encodedByteNextIndex(value, secondNext);
          if ((third & 0xc0) == 0x80) {
            int codepoint =
                ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
            if (overlongPathCharacter(codepoint)) {
              decoded.append((char) codepoint);
              i = thirdNext - 1;
              changed = true;
              continue;
            }
          }
        }
      }
      decoded.append(value.charAt(i));
    }
    return changed ? decoded.toString() : value;
  }

  private static boolean overlongPathCharacter(int codepoint) {
    return codepoint == '.' || codepoint == '/' || codepoint == '\\';
  }

  private static int encodedByteValue(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return -1;
    }
    char ch = value.charAt(index);
    if (ch == '%' && index + 2 < value.length()) {
      int high = Character.digit(value.charAt(index + 1), 16);
      int low = Character.digit(value.charAt(index + 2), 16);
      if (high >= 0 && low >= 0) {
        return (high << 4) + low;
      }
    }
    return ch <= 0xff ? ch : -1;
  }

  private static int encodedByteNextIndex(String value, int index) {
    if (index < 0 || index >= value.length()) {
      return value.length();
    }
    char ch = value.charAt(index);
    if (ch == '%'
        && index + 2 < value.length()
        && Character.digit(value.charAt(index + 1), 16) >= 0
        && Character.digit(value.charAt(index + 2), 16) >= 0) {
      return index + 3;
    }
    return index + 1;
  }

  private static String decodeUnicodeEscapes(String value) {
    if (value == null || lower(value).indexOf("%u") < 0) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '%'
          && i + 5 < value.length()
          && (value.charAt(i + 1) == 'u' || value.charAt(i + 1) == 'U')) {
        int codepoint = 0;
        boolean valid = true;
        for (int offset = 2; offset < 6; offset++) {
          int digit = Character.digit(value.charAt(i + offset), 16);
          if (digit < 0) {
            valid = false;
            break;
          }
          codepoint = (codepoint << 4) + digit;
        }
        if (valid) {
          decoded.append((char) codepoint);
          i += 5;
          continue;
        }
      }
      decoded.append(ch);
    }
    return decoded.toString();
  }

  private static String lowByteUnicodeDecode(String value) {
    if (value == null || value.isBlank()) {
      return value == null ? "" : value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    boolean changed = false;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch > 0x7f) {
        decoded.append((char) (ch & 0xff));
        changed = true;
      } else {
        decoded.append(ch);
      }
    }
    return changed ? decoded.toString() : value;
  }

  private static boolean dangerousDeserializationType(String className) {
    if (className.isBlank()) {
      return false;
    }
    if (DESERIALIZATION_BLACKLIST.contains(className)) {
      return true;
    }
    if (deserializationGadgetType(className)) {
      return true;
    }
    for (String prefix : DESERIALIZATION_TYPE_PREFIXES) {
      if (className.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static boolean dangerousProtocolInstantiationType(String className) {
    return dangerousDeserializationType(className)
        || PROTOCOL_CONFIG_INSTANTIATION_TYPES.contains(className);
  }

  private static boolean dangerousPolymorphicType(String className) {
    return POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || dangerousDeserializationType(className);
  }

  private static boolean dangerousHessianType(String className) {
    return dangerousDeserializationType(className)
        || POLYMORPHIC_CONSTRUCTION_BLACKLIST.contains(className)
        || PROTOCOL_CONFIG_INSTANTIATION_TYPES.contains(className);
  }

  private static boolean deserializationGadgetType(String className) {
    for (String prefix : DESERIALIZATION_GADGET_PREFIXES) {
      if (className.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static boolean suspiciousRmiRemoteBindType(String className) {
    String normalized = lower(className);
    return normalized.contains("$proxy")
        || normalized.startsWith("jdk.proxy")
        || normalized.startsWith("com.sun.proxy.")
        || normalized.equals("sun.rmi.server.unicastref")
        || normalized.equals("sun.rmi.server.unicastref2")
        || normalized.equals("sun.rmi.server.remoteobjectinvocationhandler")
        || normalized.equals("sun.rmi.transport.liveref")
        || normalized.equals("sun.rmi.transport.tcp.tcpendpoint")
        || normalized.endsWith(".rmisocketfactory");
  }

  private static boolean rmiRegistryTransportStack(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return false;
    }
    boolean registry = false;
    boolean transport = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.equals("sun.rmi.registry.registryimpl")
          || normalized.equals("sun.rmi.registry.registryimpl_skel")) {
        registry = true;
      }
      if (normalized.startsWith("sun.rmi.server.unicastserverref")
          || normalized.startsWith("sun.rmi.transport.")
          || normalized.startsWith("sun.rmi.transport.tcp.")) {
        transport = true;
      }
    }
    return registry && transport;
  }

  private static Optional<String> rmiTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean serverDispatch = false;
    boolean transport = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("sun.rmi.server.unicastserverref")
          || normalized.startsWith("sun.rmi.registry.registryimpl")
          || normalized.startsWith("java.rmi.server.remoteobject")) {
        serverDispatch = true;
      }
      if (normalized.startsWith("sun.rmi.transport.")
          || normalized.startsWith("sun.rmi.transport.tcp.")) {
        transport = true;
      }
    }
    return serverDispatch && transport ? Optional.of("rmi-transport") : Optional.empty();
  }

  private static Optional<String> remotingTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean weblogicT3 = false;
    boolean weblogicIiop = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("weblogic.rjvm.")
          || normalized.startsWith("weblogic.socket.")
          || normalized.startsWith("weblogic.protocol.")) {
        weblogicT3 = true;
      }
      if (normalized.startsWith("weblogic.iiop.")
          || normalized.startsWith("weblogic.corba.")
          || normalized.startsWith("weblogic.rmi.internal.")) {
        weblogicIiop = true;
      }
      if (normalized.contains("inboundmsgabbrev")
          || normalized.contains("msgabbrev")
          || normalized.contains("iiopinputstream")
          || normalized.contains("serverchannelinputstream")
          || normalized.startsWith("weblogic.utils.io.")) {
        objectStream = true;
      }
    }
    if (objectStream && weblogicT3) {
      return Optional.of("weblogic-t3");
    }
    if (objectStream && weblogicIiop) {
      return Optional.of("weblogic-iiop");
    }
    return Optional.empty();
  }

  private static Optional<String> jmsObjectMessageFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean objectMessage = false;
    boolean objectStream = false;
    String provider = "";
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.contains(".objectmessage")
          || normalized.endsWith("activemqobjectmessage")
          || normalized.endsWith("messagebody")) {
        objectMessage = true;
      }
      if (normalized.contains("objectinputstream")
          || normalized.contains("classloadingawareobjectinputstream")) {
        objectStream = true;
      }
      if (provider.isBlank() && normalized.startsWith("org.apache.activemq.")) {
        provider = "activemq-object-message";
      } else if (provider.isBlank() && normalized.startsWith("org.apache.qpid.jms.")) {
        provider = "qpid-jms-object-message";
      } else if (provider.isBlank() && normalized.startsWith("com.sun.messaging.jms.")) {
        provider = "openmq-object-message";
      } else if (provider.isBlank() && normalized.startsWith("com.ibm.msg.client.jms.")) {
        provider = "ibm-mq-object-message";
      }
    }
    return !provider.isBlank() && objectMessage && objectStream
        ? Optional.of(provider)
        : Optional.empty();
  }

  private static Optional<String> signedObjectRemotingFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean cli = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("hudson.cli.")
          || normalized.startsWith("jenkins.cli.")
          || normalized.startsWith("hudson.remoting.")
          || normalized.startsWith("org.jenkinsci.remoting.")) {
        cli = true;
      }
      if (normalized.contains("objectinputstream")
          || normalized.contains("objectinputstreamex")
          || normalized.contains("remoting")) {
        objectStream = true;
      }
    }
    return cli && objectStream ? Optional.of("jenkins-cli-remoting") : Optional.empty();
  }

  private static Optional<String> webflowClientStateFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    boolean cas = false;
    boolean webflow = false;
    boolean clientState = false;
    boolean objectStream = false;
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.jasig.cas.") || normalized.startsWith("org.apereo.cas.")) {
        cas = true;
      }
      if (normalized.startsWith("org.springframework.webflow.")
          || normalized.contains("webflow")) {
        webflow = true;
      }
      if (normalized.contains("clientflowexecution")
          || normalized.contains("flowexecutionsnapshot")
          || normalized.contains("encryptedtranscoder")
          || normalized.contains("serializedflowexecution")) {
        clientState = true;
      }
      if (normalized.contains("objectinputstream") || normalized.contains("readobject")) {
        objectStream = true;
      }
    }
    if (objectStream && clientState && (cas || webflow)) {
      return Optional.of(cas ? "cas-webflow-state" : "spring-webflow-client-state");
    }
    return Optional.empty();
  }

	  private static Optional<String> clusterMessageTransportFrame(List<String> stackClassNames) {
	    if (stackClassNames == null) {
	      return Optional.empty();
	    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.apache.catalina.tribes.")
          || normalized.startsWith("org.apache.catalina.ha.")) {
        return Optional.of("tomcat-tribes");
      }
      if (normalized.startsWith("org.jgroups.")
          || normalized.startsWith("org.infinispan.remoting.")) {
        return Optional.of("jgroups");
      }
      if (normalized.startsWith("com.hazelcast.internal.serialization.")
          || normalized.startsWith("com.hazelcast.nio.serialization.")) {
        return Optional.of("hazelcast");
      }
	    }
	    return Optional.empty();
	  }

	  private static Optional<String> clusterSecurityInterceptorFrame(List<String> stackClassNames) {
	    if (stackClassNames == null) {
	      return Optional.empty();
	    }
	    for (String frame : stackClassNames) {
	      String normalized = lower(frame).replace('/', '.');
	      if (normalized.equals("org.apache.catalina.tribes.group.interceptors.encryptinterceptor")) {
	        return Optional.of("tomcat-tribes-encrypt");
	      }
	    }
	    return Optional.empty();
	  }

	  private static Optional<String> loggingMessageTransportFrame(List<String> stackClassNames) {
    if (stackClassNames == null) {
      return Optional.empty();
    }
    for (String frame : stackClassNames) {
      String normalized = lower(frame).replace('/', '.');
      if (normalized.startsWith("org.apache.logging.log4j.core.net.server.")
          || normalized.startsWith("org.apache.logging.log4j.core.net.")
          || normalized.startsWith("org.apache.log4j.net.")) {
        return Optional.of("log4j-socket");
      }
    }
    return Optional.empty();
  }

  private static String httpObjectStreamSource(
      String streamClassName, String contentType, List<String> stackClassNames) {
    String stream = lower(streamClassName);
    if (stream.contains("servletinputstream")
        || stream.contains("coyoteinputstream")
        || stream.contains("servletrequestinputstream")
        || stream.contains("requestinputstream")
        || stream.contains("httpinput")) {
      return "servlet-input-stream";
    }
    String normalizedContentType = lower(contentType);
    if (normalizedContentType.contains("application/x-java-serialized-object")
        || normalizedContentType.contains("application/x-java")) {
      return "serialized-content-type";
    }
    List<String> safeStack = stackClassNames == null ? List.of() : stackClassNames;
    for (String className : safeStack) {
      String item = lower(className);
      if ((item.contains("readonlyaccessfilter")
              || item.contains("jmxinvokerservlet")
              || item.contains("org.jboss.invocation.http.servlet.invokerservlet")
              || item.contains("httpserverilservlet"))
          && (item.contains("jboss") || item.contains("invoker") || item.contains("httpil"))) {
        return "middleware-http-invoker";
      }
    }
    return "";
  }

  private static boolean suspiciousFileBackedSessionId(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return false;
    }
    String normalized = sessionId.trim().replace('\\', '/');
    String lower = normalized.toLowerCase(Locale.ROOT);
    return lower.startsWith(".")
        || lower.contains("..")
        || lower.contains("/")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c");
  }

  private static Optional<String> remoteConfigArgument(List<String> arguments) {
    if (arguments == null || arguments.isEmpty()) {
      return Optional.empty();
    }
    for (String argument : arguments) {
      if (argument == null || argument.isBlank()) {
        continue;
      }
      String normalized = argument.trim();
      if (remoteConfigScheme(normalized).isPresent()) {
        return Optional.of(normalized);
      }
    }
    return Optional.empty();
  }

  private static Optional<String> remoteConfigScheme(String location) {
    if (location == null || location.isBlank()) {
      return Optional.empty();
    }
    String inspected = lower(location.trim());
    while (inspected.startsWith("xbean:")
        || inspected.startsWith("spring:")
        || inspected.startsWith("classpath*:")) {
      int colon = inspected.indexOf(':');
      inspected = inspected.substring(colon + 1);
    }
    if (inspected.startsWith("jar:")) {
      inspected = inspected.substring("jar:".length());
      int bang = inspected.indexOf("!/");
      if (bang >= 0) {
        inspected = inspected.substring(0, bang);
      }
    }
    try {
      String scheme = lower(URI.create(inspected).getScheme());
      return REMOTE_CONFIG_PROTOCOLS.contains(scheme) ? Optional.of(scheme) : Optional.empty();
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private static boolean isXmlDecoderStack(List<String> stackClassNames) {
    if (stackClassNames == null || stackClassNames.isEmpty()) {
      return false;
    }
    for (String className : stackClassNames) {
      if (className == null) {
        continue;
      }
      if (className.equals("java.beans.XMLDecoder")
          || className.startsWith("com.sun.beans.decoder.")) {
        return true;
      }
    }
    return false;
  }

  private static String normalizeJavaTypeName(String className) {
    if (className == null) {
      return "";
    }
    String normalized = className.trim().replace('/', '.');
    while (normalized.startsWith("[")) {
      normalized = normalized.startsWith("[L") ? normalized.substring(2) : normalized.substring(1);
    }
    if (normalized.endsWith(";")) {
      while (normalized.startsWith("L") && normalized.length() > 1) {
        normalized = normalized.substring(1);
      }
      while (normalized.endsWith(";")) {
        normalized = normalized.substring(0, normalized.length() - 1);
      }
    }
    return normalized;
  }

  private static Optional<String> argumentFileExpansionTarget(String argument) {
    if (argument == null || argument.isBlank()) {
      return Optional.empty();
    }
    String trimmed = argument.trim();
    if (!trimmed.startsWith("@") || trimmed.length() == 1) {
      return Optional.empty();
    }
    String target = trimmed.substring(1).trim();
    if (target.length() >= 2) {
      char first = target.charAt(0);
      char last = target.charAt(target.length() - 1);
      if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        target = target.substring(1, target.length() - 1).trim();
      }
    }
    return target.isBlank() ? Optional.empty() : Optional.of(target);
  }

  private static boolean dangerousArgumentFilePath(String path) {
    String normalized = normalizePath(path);
    if (normalized.isBlank()) {
      return false;
    }
    String pathShape = path == null ? "" : path.trim().replace('\\', '/');
    if (!isAbsolutePathLike(pathShape) && !containsParentSegment(pathShape)) {
      return false;
    }
    if (DANGEROUS_FILE_READ.matcher(normalized).find()) {
      return true;
    }
    if (normalized.startsWith("/proc/")
        || normalized.startsWith("/etc/")
        || normalized.startsWith("/root/")
        || normalized.contains("/.ssh/")) {
      return true;
    }
    return looksLikeApplicationSecretPath(normalized);
  }

  private static boolean isAbsolutePathLike(String path) {
    return path.startsWith("/") || WINDOWS_ABSOLUTE_PATH.matcher(path).matches();
  }

  private static boolean looksLikeApplicationSecretPath(String path) {
    if (path.endsWith("/secret.key")
        || path.endsWith("/master.key")
        || path.endsWith("/credentials.xml")
        || path.endsWith("/identity.key.enc")
        || path.endsWith("/hudson.util.secret")) {
      return true;
    }
    return path.contains("/secrets/")
        && (path.endsWith(".key")
            || path.endsWith(".key.enc")
            || path.endsWith(".secret")
            || path.endsWith(".credentials"));
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

  private static String archivePath(String path) {
    return path == null ? "" : path.trim().replace('\\', '/');
  }

  private static boolean dangerousArchiveEntry(String entry) {
    return containsParentSegment(entry)
        || entry.startsWith("/")
        || entry.startsWith("//")
        || WINDOWS_ABSOLUTE_PATH.matcher(entry).matches()
        || entry.indexOf('\0') >= 0;
  }

  private static boolean dangerousUploadFilename(String filename) {
    if (filename == null || filename.isBlank()) {
      return false;
    }
    List<String> variants = new ArrayList<>();
    addVariant(variants, filename);
    addVariant(variants, percentDecode(filename));
    addVariant(variants, percentDecode(percentDecode(filename)));
    addVariant(variants, decodeUnicodeEscapes(filename));
    for (String variant : variants) {
      String normalized = variant.trim().replace('\\', '/');
      if (normalized.indexOf('\0') >= 0
          || normalized.startsWith("/")
          || normalized.startsWith("//")
          || containsParentSegment(normalized)) {
        return true;
      }
    }
    return false;
  }

  private static boolean remoteJobSubmissionContext(
      RequestContext request, String mechanism, String descriptor) {
    String normalizedMechanism = lower(mechanism).replaceAll("[^a-z0-9]", "");
    if (REMOTE_JOB_MECHANISMS.contains(normalizedMechanism)) {
      return true;
    }
    String uri = lower(request.uri());
    if (uri.contains("/v1/submissions")
        || uri.contains("/ws/v1/cluster/apps")
        || uri.contains("/cluster/apps")) {
      return true;
    }
    boolean term = containsPathToken(uri, REMOTE_JOB_PATH_TERMS);
    boolean action = containsPathToken(uri, REMOTE_JOB_PATH_ACTIONS);
    if ((term && action) || (uri.contains("job") && uri.contains("submission"))) {
      return remoteJobDescriptorFields(descriptor);
    }
    for (String name : request.parameters().keySet()) {
      String normalizedName = normalizeParameterName(name);
      if (normalizedName.equals("appresource")
          || normalizedName.equals("mainclass")
          || normalizedName.equals("sparkjars")
          || normalizedName.equals("applicationid")) {
        return true;
      }
    }
    return false;
  }

  private static boolean remoteJobDescriptorFields(String descriptor) {
    String normalized = lower(descriptor);
    return normalized.contains("appresource")
        || normalized.contains("mainclass")
        || normalized.contains("spark.jars")
        || normalized.contains("am-container-spec")
        || normalized.contains("application-id")
        || normalized.contains("gluesource");
  }

  private static boolean dangerousRemoteJobCommand(String command) {
    if (command == null || command.isBlank()) {
      return false;
    }
    String normalized = command.trim();
    return COMMAND_COMMON.matcher(normalized).find()
        || (COMMAND_META.matcher(normalized).find()
            && REMOTE_JOB_SHELL_COMMAND.matcher(normalized).find());
  }

  private static Optional<String> javaArchiveUploadContext(RequestContext request) {
    if (request == null || !request.active()) {
      return Optional.empty();
    }
    String uri = lower(request.uri());
    boolean term = containsPathToken(uri, JAVA_ARCHIVE_UPLOAD_TERMS);
    boolean action = containsPathToken(uri, JAVA_ARCHIVE_UPLOAD_ACTIONS);
    if (term && action) {
      return Optional.of("uri:" + abbreviate(request.uri()));
    }
    if (uri.contains("/jars/") || uri.endsWith("/jars") || uri.contains("/plugin/")) {
      return Optional.of("uri:" + abbreviate(request.uri()));
    }
    for (String name : request.parameters().keySet()) {
      String normalized = normalizeParameterName(name);
      if (JAVA_ARCHIVE_UPLOAD_PARAMETERS.contains(normalized)) {
        return Optional.of("parameter:" + abbreviate(name));
      }
    }
    return Optional.empty();
  }

  private static boolean containsPathToken(String path, Set<String> tokens) {
    if (path == null || path.isBlank()) {
      return false;
    }
    for (String segment : path.split("[/;?&#._=-]+")) {
      if (tokens.contains(segment)) {
        return true;
      }
    }
    return false;
  }

  private static boolean targetUsesDangerousArchiveEntry(String entry, String target) {
    String lowerEntry = lower(entry);
    String lowerTarget = lower(target);
    return containsParentSegment(target)
        || target.indexOf('\0') >= 0
        || lowerTarget.contains(lowerEntry);
  }

  private static boolean containsParentSegment(String path) {
    for (String segment : path.split("/+")) {
      if (segment.equals("..")) {
        return true;
      }
    }
    return false;
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

  private static String extensionOf(String value) {
    String normalized = lower(value);
    int query = normalized.indexOf('?');
    if (query >= 0) {
      normalized = normalized.substring(0, query);
    }
    int fragment = normalized.indexOf('#');
    if (fragment >= 0) {
      normalized = normalized.substring(0, fragment);
    }
    int dot = normalized.lastIndexOf('.');
    if (dot < 0 || dot == normalized.length() - 1) {
      return "";
    }
    return normalized.substring(dot + 1);
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
