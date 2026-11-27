#!/usr/bin/env bash
# Request bodies on real servlet containers. An application reads a JSON body itself (through the container's
# input stream, through Tomcat's reader, or through Spring MVC's @RequestBody binding) and puts a field of it into
# an inline shell program. Without the agent the attack runs; with the primary agent (JDK 21) and with the java17
# line (JDK 17) it is blocked, and the benign twin passes:
#
#   Tomcat 9.0  (javax)    playground-java17.war         /body/ping, /body/ping-reader, /body/patch
#   Tomcat 10.1 (jakarta)  playground-java17-jakarta.war  the same
#   Tomcat 11.0 (jakarta)  playground-java17-jakarta.war  the same
#   Spring Boot 3.5        playground-spring-body          POST /ping with @RequestBody, on Tomcat 10.1, Jetty 12
#                                                          and Undertow 2.3; PATCH /customers/1 and
#                                                          POST /app/rest/debug/processes only read their body
#
# A block is checked for what it leaves: a fresh event that names the rule and carries none of the body's text, the
# status the client gets, and, for a block thrown from inside the application's read (a rule on the body alone),
# what follows it. Each server runs one worker thread (Jetty a small pool) so that the requests after the block run
# on the thread that threw it: on the same curl connection a benign request is served (the blocked response was
# complete, whether the server kept the connection or closed it), a benign body passes with no event, and the same
# attack is blocked again (the thread's recorder started clean). The status a block gives: the primary redirects to
# its block page before it throws: Tomcat then answers its own 500 error page in place of the redirect, Jetty and
# Undertow send the redirect (302); a backport throws, and the container (or Spring's error page) answers 500.
#
# Tomcat runs from Apache's release tarballs (checked against Apache's SHA-512) inside the eclipse-temurin
# images, which keeps the versions those of probes/hook-targets/libraries.toml. Downloads are kept in
# ${OHMYRASP_ACCEPTANCE_CACHE:-$HOME/.cache/ohmyrasp-acceptance}; logs and event files in logs/request-body/.
# OHMYRASP_AGENT_JAR runs every agent scenario with that one JAR (the universal JAR picks the line per JDK).
# OHMYRASP_REQUEST_BODY_ONLY=<extended regex> runs only the scenarios whose name matches it.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=acceptance/lib/agent-build.sh
source acceptance/lib/agent-build.sh

primary_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-jdk25/build/libs/ohmyrasp-agent.jar")"
java17_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar")"
javax_war="$(pwd)/playground-java17/build/libs/playground-java17.war"
jakarta_war="$(pwd)/playground-java17-jakarta/build/libs/playground-java17-jakarta.war"
spring_lib="$(pwd)/playground-spring-body/build/install/playground-spring-body/lib"
spring_jetty_lib="$(pwd)/playground-spring-body/build/install-jetty/lib"
spring_undertow_lib="$(pwd)/playground-spring-body/build/install-undertow/lib"
only="${OHMYRASP_REQUEST_BODY_ONLY:-.}"
cache="${OHMYRASP_ACCEPTANCE_CACHE:-$HOME/.cache/ohmyrasp-acceptance}"
port_base="${OHMYRASP_REQUEST_BODY_PORT:-18930}"
logs="$(pwd)/logs/request-body"
prefix="ohmyrasp-request-body-$$"

ohmyrasp_build :agent-jdk25:agentJar :agent-java17:agentJava17Jar
# The applications build even when OHMYRASP_AGENT_JAR names a prebuilt agent.
if [[ -n "${OHMYRASP_AGENT_JAR:-}" && "${OHMYRASP_SKIP_AGENT_BUILD:-}" != 1 ]]; then
  OHMYRASP_AGENT_JAR="" ohmyrasp_build :playground-java17:war :playground-java17-jakarta:war \
    :playground-spring-body:installDist :playground-spring-body:installJetty :playground-spring-body:installUndertow
else
  ohmyrasp_build :playground-java17:war :playground-java17-jakarta:war \
    :playground-spring-body:installDist :playground-spring-body:installJetty :playground-spring-body:installUndertow
fi
for built in "$javax_war" "$jakarta_war" "$spring_lib" "$spring_jetty_lib" "$spring_undertow_lib"; do
  [[ -e "$built" ]] || { echo "missing $built: build it first" >&2; exit 1; }
done

rm -rf "$logs"
mkdir -p "$logs" "$cache"
containers=()
cleanup() {
  for name in "${containers[@]}"; do
    docker logs "$name" > "$logs/$name.container.log" 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

tomcat_tarball() {
  local version=$1 major=${1%%.*}
  local file="$cache/apache-tomcat-$version.tar.gz"
  local url="https://archive.apache.org/dist/tomcat/tomcat-$major/v$version/bin/apache-tomcat-$version.tar.gz"
  if [[ ! -f "$file" ]]; then
    curl -fsSL -o "$file.part" "$url"
    curl -fsSL -o "$file.sha512" "$url.sha512"
    (cd "$cache" && echo "$(awk '{print $1}' "$file.sha512")  apache-tomcat-$version.tar.gz.part" | sha512sum -c - >/dev/null)
    mv "$file.part" "$file"
  fi
  printf '%s\n' "$file"
}

agent_options() {
  local jar=$1
  if [[ -z "$jar" ]]; then return; fi
  printf '%s' "-javaagent:/opt/ohmyrasp/agent.jar -Dohmyrasp.standalone=true -Dohmyrasp.mode=block"
  printf '%s' " -Dohmyrasp.control=none -Dohmyrasp.log.sync=true -Dohmyrasp.log=/opt/ohmyrasp/logs/events.jsonl"
}

# start_tomcat <name> <port> <tomcat version> <war> <jdk image> <agent jar or "">
start_tomcat() {
  local name=$1 port=$2 version=$3 war=$4 image=$5 jar=$6
  local dir="$logs/$name"
  mkdir -p "$dir/events"
  tar -xzf "$(tomcat_tarball "$version")" -C "$dir"
  rm -rf "$dir/apache-tomcat-$version/webapps/"*
  # One worker thread: the requests after a block run on the thread that threw it.
  sed -i 's/<Connector port="8080"/<Connector port="8080" maxThreads="1" minSpareThreads="1"/' \
    "$dir/apache-tomcat-$version/conf/server.xml"
  cp "$war" "$dir/apache-tomcat-$version/webapps/ROOT.war"
  : > "$dir/events/events.jsonl"
  local mounts=(-v "$dir/apache-tomcat-$version:/opt/tomcat" -v "$dir/events:/opt/ohmyrasp/logs")
  if [[ -n "$jar" ]]; then mounts+=(-v "$jar:/opt/ohmyrasp/agent.jar:ro"); fi
  docker run -d --name "$prefix-$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" "${mounts[@]}" \
    -e CATALINA_OPTS="$(agent_options "$jar")" "$image" /opt/tomcat/bin/catalina.sh run >/dev/null
  containers+=("$prefix-$name")
  wait_for "$name" "http://127.0.0.1:$port/body/health"
}

# start_spring <name> <port> <server: tomcat, jetty or undertow> <jdk image> <agent jar or "">
start_spring() {
  local name=$1 port=$2 server=$3 image=$4 jar=$5
  local dir="$logs/$name" lib threads
  case "$server" in
    tomcat) lib=$spring_lib; threads="--server.tomcat.threads.max=1 --server.tomcat.threads.min-spare=1" ;;
    # Jetty takes acceptor and selector threads from the same pool: 8 leaves it a few workers.
    jetty) lib=$spring_jetty_lib; threads="--server.jetty.threads.max=8 --server.jetty.threads.min=8" ;;
    undertow) lib=$spring_undertow_lib; threads="--server.undertow.threads.io=1 --server.undertow.threads.worker=1" ;;
  esac
  mkdir -p "$dir/events"
  : > "$dir/events/events.jsonl"
  local mounts=(-v "$lib:/opt/app/lib:ro" -v "$dir/events:/opt/ohmyrasp/logs")
  if [[ -n "$jar" ]]; then mounts+=(-v "$jar:/opt/ohmyrasp/agent.jar:ro"); fi
  # shellcheck disable=SC2046,SC2086
  docker run -d --name "$prefix-$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" "${mounts[@]}" "$image" \
    java $(agent_options "$jar") -cp '/opt/app/lib/*' io.ohmyrasp.playground.springbody.SpringBodyApplication \
    $threads >/dev/null
  containers+=("$prefix-$name")
  wait_for "$name" "http://127.0.0.1:$port/health"
}

wait_for() {
  local name=$1 url=$2
  for _ in $(seq 1 180); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return; fi
    sleep 1
  done
  echo "$name did not answer at $url" >&2
  docker logs "$prefix-$name" 2>&1 | tail -30 >&2
  exit 1
}

failures=0
content_type() {
  if [[ "$1" == */patch || "$1" == /customers/* ]]; then echo application/json-patch+json; else echo application/json; fi
}

# send <name> <port> <method> <path> <body> -> sets status and response; status 000 is no response at all
send() {
  local name=$1 port=$2 method=$3 path=$4 body=$5
  local out="$logs/$name/response.$RANDOM"
  status=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" -H "Content-Type: $(content_type "$path")" \
    --data-binary "$body" "http://127.0.0.1:$port$path" 2>/dev/null || true)
  [[ -n "$status" ]] || status=000
  response=$(cat "$out" 2>/dev/null || true)
}

# The text of the bodies below that no event's message or details may carry: the canary password and pieces of the
# attacks' values. (The request's own headers, the Host header among them, are not body text.)
leaked() {
  python3 -c '
import json, re, sys
for line in sys.stdin:
    if not line.strip():
        continue
    event = json.loads(line)
    texts = [event.get("message", "")] + [v for v in (event.get("details") or {}).values() if isinstance(v, str)]
    for text in texts:
        found = re.search(r"hunter2-Secret|127\.0\.0\.1|getRuntime", text)
        if found:
            print(found.group(0))
            sys.exit()
' <<<"$1"
}

expect_runs() {  # the request is served and the injected command ran (no agent)
  local name=$1 port=$2 path=$3 body=$4
  send "$name" "$port" POST "$path" "$body"
  if [[ "$status" == 200 && "$response" == *"uid="* ]]; then
    echo "ok   $name $path: without the agent the injected command ran"
  else
    echo "FAIL $name $path: expected the attack to run without the agent; status $status: ${response:0:200}" >&2
    failures=$((failures + 1))
  fi
}

expect_passes() {  # the benign twin is served unchanged and leaves no event
  local name=$1 port=$2 method=$3 path=$4 body=$5 needle=$6
  local events="$logs/$name/events/events.jsonl" before
  before=$(wc -l < "$events")
  send "$name" "$port" "$method" "$path" "$body"
  if [[ "$status" == 200 && "$response" == *"$needle"* && "$(wc -l < "$events")" == "$before" ]]; then
    echo "ok   $name $method $path: benign body passed"
  else
    echo "FAIL $name $method $path: benign body; status $status, events $before -> $(wc -l < "$events"): ${response:0:200}" >&2
    failures=$((failures + 1))
  fi
}

# expect_blocked <name> <port> <method> <path> <body> <rule> <status>: the request is stopped with <status>, the
# command never ran, a fresh event names the rule with action block, and no fresh event carries the body's text
expect_blocked() {
  local name=$1 port=$2 method=$3 path=$4 body=$5 rule=$6 expected=$7
  local events="$logs/$name/events/events.jsonl" before fresh leak
  before=$(wc -l < "$events")
  send "$name" "$port" "$method" "$path" "$body"
  fresh=$(tail -n +"$((before + 1))" "$events")
  leak=$(leaked "$fresh")
  if [[ "$status" == "$expected" && "$response" != *"uid="* ]] \
      && grep -q "\"algorithm\":\"$rule\",\"action\":\"block\"" <<<"$fresh"; then
    if [[ -n "$leak" ]]; then
      echo "FAIL $name $method $path: an event carries the body's text ($leak)" >&2
      failures=$((failures + 1))
    else
      echo "ok   $name $method $path: blocked by $rule (status $status)"
    fi
  else
    echo "FAIL $name $method $path: expected a block by $rule with status $expected; status $status: ${response:0:200}" >&2
    grep -o '"algorithm":"[^"]*","action":"[^"]*"' <<<"$fresh" >&2 || true
    failures=$((failures + 1))
  fi
}

# expect_block_contract <name> <port> <method> <path> <attack> <rule> <status> <benign path> <benign body> <needle>
# A block thrown from inside the application's read, and what follows it on the server's worker thread.
expect_block_contract() {
  local name=$1 port=$2 method=$3 path=$4 attack=$5 rule=$6 expected=$7 benign_path=$8 benign=$9 needle=${10}
  local events="$logs/$name/events/events.jsonl" before fresh out1="$logs/$name/pair1.$RANDOM" out2="$logs/$name/pair2.$RANDOM"
  local result code=0 first second connects
  before=$(wc -l < "$events")
  result=$(curl -sS -o "$out1" -w '%{http_code} %{num_connects}\n' -X "$method" -H "Content-Type: $(content_type "$path")" \
      --data-binary "$attack" "http://127.0.0.1:$port$path" \
    --next -sS -o "$out2" -w '%{http_code} %{num_connects}\n' -X POST -H "Content-Type: $(content_type "$benign_path")" \
      --data-binary "$benign" "http://127.0.0.1:$port$benign_path" 2>"$logs/$name/pair.err") || code=$?
  first=$(sed -n 1p <<<"$result" | cut -d' ' -f1)
  second=$(sed -n 2p <<<"$result" | cut -d' ' -f1)
  connects=$(sed -n 2p <<<"$result" | cut -d' ' -f2)
  fresh=$(tail -n +"$((before + 1))" "$events")
  if [[ "$code" == 0 && "$first" == "$expected" && "$second" == 200 && "$(cat "$out2")" == *"$needle"* ]] \
      && grep -q "\"algorithm\":\"$rule\",\"action\":\"block\"" <<<"$fresh" && [[ -z "$(leaked "$fresh")" ]]; then
    local kept="kept"; [[ "$connects" == 0 ]] || kept="closed by the server, and the next request reconnected"
    echo "ok   $name $method $path: blocked in the read by $rule (status $first); connection $kept; next request served"
  else
    echo "FAIL $name $method $path: block in the read; curl exit $code, statuses '$first' '$second' (want $expected, 200): $(head -c 200 "$out2" 2>/dev/null)" >&2
    cat "$logs/$name/pair.err" >&2 || true
    failures=$((failures + 1))
  fi
  # On the same worker thread: a benign body passes with no event, and the attack is blocked again.
  expect_passes "$name" "$port" POST "$benign_path" "$benign" "$needle"
  expect_blocked "$name" "$port" "$method" "$path" "$attack" "$rule" "$expected"
}

attack='{"username":"a","password":"hunter2-Secret","host":"127.0.0.1; id"}'
benign='{"username":"a","password":"hunter2-Secret","host":"127.0.0.1"}'
debug_attack='{"username":"a","password":"hunter2-Secret","exePath":"id"}'
patch_attack='[{"op":"replace","path":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{105,100}))/lastname","value":"vulhub"}]'
patch_benign='[{"op":"replace","path":"/lastname","value":"vulhub"}]'

# name tomcat-version war jdk-image agent-jar command-rule body-only-rule block-status
tomcat_scenarios=(
  "tomcat9-baseline 9.0.124 $javax_war eclipse-temurin:21 - - - -"
  "tomcat9-primary 9.0.124 $javax_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression 500"
  "tomcat9-java17 9.0.124 $javax_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta - 500"
  "tomcat10-primary 10.1.62 $jakarta_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression 500"
  "tomcat10-java17 10.1.62 $jakarta_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta - 500"
  "tomcat11-primary 11.0.29 $jakarta_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression 500"
  "tomcat11-java17 11.0.29 $jakarta_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta - 500"
)
port=$port_base
for scenario in "${tomcat_scenarios[@]}"; do
  read -r name version war image jar rule body_rule blocked <<<"$scenario"
  [[ "$jar" == - ]] && jar=""
  if ! [[ "$name" =~ $only ]]; then port=$((port + 1)); continue; fi
  start_tomcat "$name" "$port" "$version" "$war" "$image" "$jar"
  if [[ -z "$jar" ]]; then
    expect_runs "$name" "$port" /body/ping "$attack"
    expect_runs "$name" "$port" /body/ping-reader "$attack"
  else
    expect_passes "$name" "$port" POST /body/ping "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /body/ping "$attack" "$rule" "$blocked"
    expect_passes "$name" "$port" POST /body/ping-reader "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /body/ping-reader "$attack" "$rule" "$blocked"
    expect_passes "$name" "$port" PATCH /body/patch "$patch_benign" patched
    if [[ "$body_rule" != - ]]; then
      expect_block_contract "$name" "$port" PATCH /body/patch "$patch_attack" "$body_rule" "$blocked" \
        /body/ping "$benign" 127.0.0.1
    fi
  fi
  port=$((port + 1))
done

# name server jdk-image agent-jar command-rule line-prefix block-status
spring_scenarios=(
  "spring-baseline tomcat eclipse-temurin:21 - - - -"
  "spring-primary tomcat eclipse-temurin:21 $primary_jar command_userinput - 500"
  "spring-java17 tomcat eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta java17_ 500"
  "spring-jetty-primary jetty eclipse-temurin:21 $primary_jar command_userinput - 302"
  "spring-jetty-java17 jetty eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta java17_ 500"
  "spring-undertow-primary undertow eclipse-temurin:21 $primary_jar command_userinput - 302"
  "spring-undertow-java17 undertow eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta java17_ 500"
)
for scenario in "${spring_scenarios[@]}"; do
  read -r name server image jar rule line blocked <<<"$scenario"
  [[ "$jar" == - ]] && jar=""
  [[ "$line" == - ]] && line=""
  if ! [[ "$name" =~ $only ]]; then port=$((port + 1)); continue; fi
  start_spring "$name" "$port" "$server" "$image" "$jar"
  if [[ -z "$jar" ]]; then
    expect_runs "$name" "$port" /ping "$attack"
  else
    expect_passes "$name" "$port" POST /ping "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /ping "$attack" "$rule" "$blocked"
    expect_block_contract "$name" "$port" POST /app/rest/debug/processes "$debug_attack" \
      "${line}request_debug_process_launch" "$blocked" /ping "$benign" 127.0.0.1
    if [[ -z "$line" ]]; then
      expect_block_contract "$name" "$port" PATCH /customers/1 "$patch_attack" request_json_patch_expression "$blocked" \
        /ping "$benign" 127.0.0.1
    fi
  fi
  port=$((port + 1))
done

if (( failures )); then
  echo "$failures request-body check(s) failed; logs in $logs" >&2
  exit 1
fi
echo "request-body acceptance passed; logs in $logs"
