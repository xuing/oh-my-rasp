#!/usr/bin/env bash
# Request bodies on real servlet containers. An application reads a JSON body itself (through the container's
# input stream, through Tomcat's reader, or through Spring MVC's @RequestBody binding) and puts a field of it into
# an inline shell program. Without the agent the attack runs; with the primary agent (JDK 21) and with the java17
# line (JDK 17) it is blocked, and the benign twin passes:
#
#   Tomcat 9.0  (javax)    playground-java17.war         /body/ping, /body/ping-reader, /body/patch
#   Tomcat 10.1 (jakarta)  playground-java17-jakarta.war  the same
#   Tomcat 11.0 (jakarta)  playground-java17-jakarta.war  the same
#   Spring Boot 3.5        playground-spring-body          POST /ping with @RequestBody
#
# Tomcat runs from Apache's release tarballs (checked against Apache's SHA-512) inside the eclipse-temurin
# images, which keeps the versions those of probes/hook-targets/libraries.toml. Downloads are kept in
# ${OHMYRASP_ACCEPTANCE_CACHE:-$HOME/.cache/ohmyrasp-acceptance}; logs and event files in logs/request-body/.
# OHMYRASP_AGENT_JAR runs every agent scenario with that one JAR (the universal JAR picks the line per JDK).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=acceptance/lib/agent-build.sh
source acceptance/lib/agent-build.sh

primary_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-jdk25/build/libs/ohmyrasp-agent.jar")"
java17_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar")"
javax_war="$(pwd)/playground-java17/build/libs/playground-java17.war"
jakarta_war="$(pwd)/playground-java17-jakarta/build/libs/playground-java17-jakarta.war"
spring_lib="$(pwd)/playground-spring-body/build/install/playground-spring-body/lib"
cache="${OHMYRASP_ACCEPTANCE_CACHE:-$HOME/.cache/ohmyrasp-acceptance}"
port_base="${OHMYRASP_REQUEST_BODY_PORT:-18930}"
logs="$(pwd)/logs/request-body"
prefix="ohmyrasp-request-body-$$"

ohmyrasp_build :agent-jdk25:agentJar :agent-java17:agentJava17Jar
# The applications build even when OHMYRASP_AGENT_JAR names a prebuilt agent.
if [[ -n "${OHMYRASP_AGENT_JAR:-}" && "${OHMYRASP_SKIP_AGENT_BUILD:-}" != 1 ]]; then
  OHMYRASP_AGENT_JAR="" ohmyrasp_build :playground-java17:war :playground-java17-jakarta:war :playground-spring-body:installDist
else
  ohmyrasp_build :playground-java17:war :playground-java17-jakarta:war :playground-spring-body:installDist
fi
for built in "$javax_war" "$jakarta_war" "$spring_lib"; do
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
  cp "$war" "$dir/apache-tomcat-$version/webapps/ROOT.war"
  : > "$dir/events/events.jsonl"
  local mounts=(-v "$dir/apache-tomcat-$version:/opt/tomcat" -v "$dir/events:/opt/ohmyrasp/logs")
  if [[ -n "$jar" ]]; then mounts+=(-v "$jar:/opt/ohmyrasp/agent.jar:ro"); fi
  docker run -d --name "$prefix-$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" "${mounts[@]}" \
    -e CATALINA_OPTS="$(agent_options "$jar")" "$image" /opt/tomcat/bin/catalina.sh run >/dev/null
  containers+=("$prefix-$name")
  wait_for "$name" "http://127.0.0.1:$port/body/health"
}

# start_spring <name> <port> <jdk image> <agent jar or "">
start_spring() {
  local name=$1 port=$2 image=$3 jar=$4
  local dir="$logs/$name"
  mkdir -p "$dir/events"
  : > "$dir/events/events.jsonl"
  local mounts=(-v "$spring_lib:/opt/app/lib:ro" -v "$dir/events:/opt/ohmyrasp/logs")
  if [[ -n "$jar" ]]; then mounts+=(-v "$jar:/opt/ohmyrasp/agent.jar:ro"); fi
  # shellcheck disable=SC2046
  docker run -d --name "$prefix-$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" "${mounts[@]}" "$image" \
    java $(agent_options "$jar") -cp '/opt/app/lib/*' io.ohmyrasp.playground.springbody.SpringBodyApplication >/dev/null
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
# send <name> <port> <method> <path> <body> -> sets status and response
send() {
  local name=$1 port=$2 method=$3 path=$4 body=$5
  local out="$logs/$name/response.$RANDOM"
  local type=application/json
  if [[ "$path" == */patch ]]; then type=application/json-patch+json; fi
  status=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" -H "Content-Type: $type" \
    --data-binary "$body" "http://127.0.0.1:$port$path" 2>/dev/null || true)
  response=$(cat "$out" 2>/dev/null || true)
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

expect_blocked() {  # the request is stopped, the command never ran, and the event names the rule
  local name=$1 port=$2 method=$3 path=$4 body=$5 rule=$6
  local events="$logs/$name/events/events.jsonl"
  send "$name" "$port" "$method" "$path" "$body"
  if [[ "$status" != 200 && "$response" != *"uid="* ]] && grep -q "\"algorithm\":\"$rule\"" "$events" \
      && grep "\"algorithm\":\"$rule\"" "$events" | grep -q '"action":"block"'; then
    if grep -q 'hunter2-Secret' "$events"; then
      echo "FAIL $name $method $path: the event file holds the body's password" >&2
      failures=$((failures + 1))
    else
      echo "ok   $name $method $path: blocked by $rule (status $status)"
    fi
  else
    echo "FAIL $name $method $path: expected a block by $rule; status $status: ${response:0:200}" >&2
    grep -o '"algorithm":"[^"]*","action":"[^"]*"' "$events" >&2 || true
    failures=$((failures + 1))
  fi
}

attack='{"username":"a","password":"hunter2-Secret","host":"127.0.0.1; id"}'
benign='{"username":"a","password":"hunter2-Secret","host":"127.0.0.1"}'
patch_attack='[{"op":"replace","path":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{105,100}))/lastname","value":"vulhub"}]'
patch_benign='[{"op":"replace","path":"/lastname","value":"vulhub"}]'

# name tomcat-version war jdk-image agent-jar command-rule body-only-rule
tomcat_scenarios=(
  "tomcat9-baseline 9.0.124 $javax_war eclipse-temurin:21 - - -"
  "tomcat9-primary 9.0.124 $javax_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression"
  "tomcat9-java17 9.0.124 $javax_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta -"
  "tomcat10-primary 10.1.62 $jakarta_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression"
  "tomcat10-java17 10.1.62 $jakarta_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta -"
  "tomcat11-primary 11.0.29 $jakarta_war eclipse-temurin:21 $primary_jar command_userinput request_json_patch_expression"
  "tomcat11-java17 11.0.29 $jakarta_war eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta -"
)
port=$port_base
for scenario in "${tomcat_scenarios[@]}"; do
  read -r name version war image jar rule body_rule <<<"$scenario"
  [[ "$jar" == - ]] && jar=""
  start_tomcat "$name" "$port" "$version" "$war" "$image" "$jar"
  if [[ -z "$jar" ]]; then
    expect_runs "$name" "$port" /body/ping "$attack"
    expect_runs "$name" "$port" /body/ping-reader "$attack"
  else
    expect_passes "$name" "$port" POST /body/ping "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /body/ping "$attack" "$rule"
    expect_passes "$name" "$port" POST /body/ping-reader "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /body/ping-reader "$attack" "$rule"
    expect_passes "$name" "$port" PATCH /body/patch "$patch_benign" patched
    if [[ "$body_rule" != - ]]; then
      expect_blocked "$name" "$port" PATCH /body/patch "$patch_attack" "$body_rule"
    fi
  fi
  port=$((port + 1))
done

spring_scenarios=(
  "spring-baseline eclipse-temurin:21 - -"
  "spring-primary eclipse-temurin:21 $primary_jar command_userinput"
  "spring-java17 eclipse-temurin:17 $java17_jar java17_command_execution_shell_meta"
)
for scenario in "${spring_scenarios[@]}"; do
  read -r name image jar rule <<<"$scenario"
  [[ "$jar" == - ]] && jar=""
  start_spring "$name" "$port" "$image" "$jar"
  if [[ -z "$jar" ]]; then
    expect_runs "$name" "$port" /ping "$attack"
  else
    expect_passes "$name" "$port" POST /ping "$benign" 127.0.0.1
    expect_blocked "$name" "$port" POST /ping "$attack" "$rule"
  fi
  port=$((port + 1))
done

if (( failures )); then
  echo "$failures request-body check(s) failed; logs in $logs" >&2
  exit 1
fi
echo "request-body acceptance passed; logs in $logs"
