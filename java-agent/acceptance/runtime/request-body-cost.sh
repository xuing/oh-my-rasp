#!/usr/bin/env bash
# What recording request bodies costs on the application's threads, on a real container: Tomcat 10.1 (jakarta)
# on JDK 21 with playground-java17-jakarta.war, whose POST|PATCH /body/size reads the whole body with
# read(byte[8192]) and reports how long that loop took on the request thread.
#
# Three configurations: no agent, the primary agent before request-body recording (OHMYRASP_BASELINE_AGENT_JAR:
# a JAR built from the commit before it; that column is left out when it is not set), and the current primary
# agent. Two requests: a 10 MB JSON body (past the cap, so most reads are the capped fast path) and a 2 KB JSON
# body (recorded whole and decided). Each runs ${OHMYRASP_COST_RUNS:-30} times after ${OHMYRASP_COST_WARMUP:-3000} 2 KB
# requests and 20 large ones warm the JIT up; the table gives
# the median and the 10th-90th percentile spread of the server-side read time and of the client's request time.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=acceptance/lib/agent-build.sh
source acceptance/lib/agent-build.sh

agent_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-jdk25/build/libs/ohmyrasp-agent.jar")"
baseline_jar="${OHMYRASP_BASELINE_AGENT_JAR:-}"
war="$(pwd)/playground-java17-jakarta/build/libs/playground-java17-jakarta.war"
cache="${OHMYRASP_ACCEPTANCE_CACHE:-$HOME/.cache/ohmyrasp-acceptance}"
runs="${OHMYRASP_COST_RUNS:-30}"
warmup="${OHMYRASP_COST_WARMUP:-3000}"
port="${OHMYRASP_REQUEST_BODY_COST_PORT:-18960}"
version=10.1.62
logs="$(pwd)/logs/request-body-cost"
name="ohmyrasp-request-body-cost-$$"

ohmyrasp_build :agent-jdk25:agentJar
if [[ -n "${OHMYRASP_AGENT_JAR:-}" && "${OHMYRASP_SKIP_AGENT_BUILD:-}" != 1 ]]; then
  OHMYRASP_AGENT_JAR="" ohmyrasp_build :playground-java17-jakarta:war
else
  ohmyrasp_build :playground-java17-jakarta:war
fi

rm -rf "$logs"
mkdir -p "$logs" "$cache"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

tarball="$cache/apache-tomcat-$version.tar.gz"
if [[ ! -f "$tarball" ]]; then
  url="https://archive.apache.org/dist/tomcat/tomcat-10/v$version/bin/apache-tomcat-$version.tar.gz"
  curl -fsSL -o "$tarball.part" "$url"
  curl -fsSL -o "$tarball.sha512" "$url.sha512"
  (cd "$cache" && echo "$(awk '{print $1}' "$tarball.sha512")  apache-tomcat-$version.tar.gz.part" | sha512sum -c - >/dev/null)
  mv "$tarball.part" "$tarball"
fi

# The bodies: 10 MB and 2 KB of JSON.
python3 - "$logs" <<'PY'
import json, sys
logs = sys.argv[1]
with open(f"{logs}/large.json", "w") as out:
    out.write('{"name":"upload","data":"' + "a" * (10 * 1024 * 1024 - 32) + '"}')
record = {"id": 1042, "customer": {"name": "Ada Lovelace", "email": "ada@example.com", "address": "12 St James's Square, London"},
          "items": [{"sku": f"SKU-{i:04d}", "qty": i % 5 + 1, "note": "gift wrap, deliver after 5pm"} for i in range(16)],
          "comment": "Please call before delivery; the door code is 4711.", "links": ["https://example.com/orders/1042"]}
text = json.dumps(record)
text = text[:-1] + ',"pad":"' + "x" * max(0, 2048 - len(text) - 10) + '"}'
open(f"{logs}/small.json", "w").write(text)
PY

measure() {  # measure <label> <agent jar or "">
  local label=$1 jar=$2 dir="$logs/$1"
  mkdir -p "$dir/events"
  tar -xzf "$tarball" -C "$dir"
  rm -rf "$dir/apache-tomcat-$version/webapps/"*
  cp "$war" "$dir/apache-tomcat-$version/webapps/ROOT.war"
  local opts="" mounts=(-v "$dir/apache-tomcat-$version:/opt/tomcat" -v "$dir/events:/opt/ohmyrasp/logs")
  if [[ -n "$jar" ]]; then
    opts="-javaagent:/opt/ohmyrasp/agent.jar -Dohmyrasp.standalone=true -Dohmyrasp.mode=block -Dohmyrasp.control=none"
    opts="$opts -Dohmyrasp.log=/opt/ohmyrasp/logs/events.jsonl"
    mounts+=(-v "$jar:/opt/ohmyrasp/agent.jar:ro")
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -u "$(id -u):$(id -g)" -p "127.0.0.1:$port:8080" "${mounts[@]}" \
    -e CATALINA_OPTS="-Xms512m -Xmx512m $opts" eclipse-temurin:21 /opt/tomcat/bin/catalina.sh run >/dev/null
  for _ in $(seq 1 120); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/body/health" 2>/dev/null && break
    sleep 1
  done
  local url="http://127.0.0.1:$port/body/size"
  for _ in $(seq 1 "$warmup"); do
    curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' --data-binary "@$logs/small.json" "$url"
  done
  for _ in $(seq 1 20); do
    curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' --data-binary "@$logs/large.json" "$url"
  done
  for kind in large small; do
    for _ in $(seq 1 "$runs"); do
      curl -fsS -X POST -H 'Content-Type: application/json' --data-binary "@$logs/$kind.json" \
        -w ' client_s=%{time_total}\n' "$url" >> "$dir/$kind.txt"
    done
  done
  docker logs "$name" > "$dir/container.log" 2>&1 || true
  docker rm -f "$name" >/dev/null
  echo "measured $label"
}

measure none ""
if [[ -n "$baseline_jar" ]]; then measure before "$baseline_jar"; fi
measure after "$agent_jar"

python3 - "$logs" "$runs" <<'PY'
import re, statistics, sys
from pathlib import Path
logs, runs = Path(sys.argv[1]), int(sys.argv[2])

def pct(values, p):
    values = sorted(values)
    k = (len(values) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)

print(f"| body | configuration | server read: median | p10-p90 | client request: median | p10-p90 | runs |")
print("|---|---|---|---|---|---|---|")
for kind, label in (("large", "10 MB JSON"), ("small", "2 KB JSON")):
    for config in ("none", "before", "after"):
        f = logs / config / f"{kind}.txt"
        if not f.exists():
            continue
        server, client = [], []
        for line in f.read_text().splitlines():
            m = re.search(r"bytes=(\d+) read_ns=(\d+) client_s=([\d.]+)", line)
            if m:
                server.append(int(m.group(2)) / 1e6)
                client.append(float(m.group(3)) * 1e3)
        unit = "ms"
        print(f"| {label} | {config} | {statistics.median(server):.3f} {unit} | {pct(server, 10):.3f}-{pct(server, 90):.3f} | "
              f"{statistics.median(client):.3f} {unit} | {pct(client, 10):.3f}-{pct(client, 90):.3f} | {len(server)} |")
PY
