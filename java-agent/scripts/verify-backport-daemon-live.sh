#!/usr/bin/env bash
#
# Live, end-to-end verification of a BACKPORT agent (java8 by default) running
# against the OhMyRASP host daemon on a real Tomcat — the properties that unit
# tests (which run sync, with no control file) cannot exercise:
#
#   1. async spool drain      OHMYRASP_LOG_SYNC=false -> the agent's background
#                             writer thread flushes events the daemon tails.
#   2. control-file mode poll  the daemon writes control.json; the agent polls
#                             it and changes behavior live (no restart):
#                                 MONITOR -> attack allowed (HTTP 200), recorded
#                                 BLOCK   -> attack blocked (HTTP 500), recorded
#                                 OFF     -> allowed, nothing recorded, no telemetry
#   3. business-latency panel  benign traffic emits kind:"telemetry" samples that
#                             populate the daemon's latency percentiles.
#
# The agent (Tomcat container) and the daemon (container) share one bind-mounted
# host dir: events.jsonl (agent -> daemon) and control.json (daemon -> agent).
# Mode flips go through the daemon's console HTTP API — the real operator loop.
#
# Prereqs (build once):
#   docker build -t ohmyrasp/daemon:dev ../daemon
#   docker build --no-cache -f Dockerfile.java8 -t ohmyrasp/playground:tomcat8-java8 \
#     --build-arg TOMCAT_IMAGE=tomcat:8.5-jdk8-temurin \
#     --build-arg PLAYGROUND_PROJECT=playground-java8 \
#     --build-arg PLAYGROUND_WAR=playground-java8.war .
#   ( --no-cache matters: a cached gradle layer can bake a pre-refactor jar. )
#
# Usage:  scripts/verify-backport-daemon-live.sh
set -u

IMG="${OHMYRASP_BACKPORT_IMAGE:-ohmyrasp/playground:tomcat8-java8}"
DAEMON_IMG="${OHMYRASP_DAEMON_IMAGE:-ohmyrasp/daemon:dev}"
AGENT_JAR="${OHMYRASP_AGENT_JAR:-/opt/ohmyrasp/ohmyrasp-agent-java8.jar}"
ATTACK_PATH="${OHMYRASP_ATTACK_PATH:-/rasp/java8/command}"
HEALTH_PATH="${OHMYRASP_HEALTH_PATH:-/rasp/health}"
APP_PORT="${OHMYRASP_APP_PORT:-28092}"
CONSOLE_PORT="${OHMYRASP_CONSOLE_PORT:-28702}"
SHARED="$(mktemp -d /tmp/omr-backport-verify.XXXXXX)"
NET=omr-backport-verify-net
APP_C=omr-backport-verify-app
DAEMON=omr-backport-verify-daemon
APP="http://127.0.0.1:${APP_PORT}"
CONSOLE="http://127.0.0.1:${CONSOLE_PORT}"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
cleanup(){
  docker rm -f "$APP_C" "$DAEMON" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$SHARED" 2>/dev/null || true
}
trap cleanup EXIT

echo "== gate: image '$IMG' must contain the refactored RaspRuntime =="
if docker run --rm --entrypoint sh "$IMG" -c "jar tf '$AGENT_JAR' 2>/dev/null | grep -q RaspRuntime"; then
  ok "RaspRuntime present in agent jar (refactored backport)"
else
  no "RaspRuntime ABSENT — image is stale (rebuild with --no-cache). Aborting."
  echo "================  RESULT: PASS=$PASS  FAIL=$FAIL  ================"; exit 1
fi

chmod 777 "$SHARED"
docker network create "$NET" >/dev/null 2>&1 || true

echo "== start daemon container (writes control.json, tails events.jsonl) =="
docker run -d --name "$DAEMON" --network "$NET" -p "${CONSOLE_PORT}:7070" \
  -v "$SHARED":/opt/ohmyrasp/shared "$DAEMON_IMG" \
  --spool=/opt/ohmyrasp/shared/events.jsonl \
  --control=/opt/ohmyrasp/shared/control.json \
  --console-bind=0.0.0.0:7070 --from-start >/dev/null
for i in $(seq 1 30); do curl -sf "$CONSOLE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sf "$CONSOLE/healthz" >/dev/null 2>&1 && ok "daemon console up" || no "daemon not up"
grep -qi monitor "$SHARED/control.json" 2>/dev/null && ok "daemon wrote initial control.json (mode=monitor)" || no "no control.json"

echo "== start backport Tomcat (ASYNC: OHMYRASP_LOG_SYNC=false) =="
docker run -d --name "$APP_C" --network "$NET" -p "${APP_PORT}:8080" \
  -v "$SHARED":/opt/ohmyrasp/shared \
  -e OHMYRASP_LOG_SYNC=false \
  -e CATALINA_OPTS="-javaagent:${AGENT_JAR} -Dohmyrasp.java8.log=/opt/ohmyrasp/shared/events.jsonl -Dohmyrasp.log=/opt/ohmyrasp/shared/events.jsonl -Dohmyrasp.control=/opt/ohmyrasp/shared/control.json -Dohmyrasp.control.poll_ms=500 -Dohmyrasp.latency_sample=1 -Dohmyrasp.java8.block=true" \
  "$IMG" >/dev/null
for i in $(seq 1 60); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$APP$HEALTH_PATH")" = "200" ] && { echo "  app up ~${i}s"; break; }; sleep 1; done

echo "== Phase A: telemetry / latency panel (benign x40) =="
for i in $(seq 1 40); do curl -s -o /dev/null "$APP$HEALTH_PATH"; done
sleep 2
TEL=$(grep -c '"kind":"telemetry"' "$SHARED/events.jsonl" 2>/dev/null || echo 0)
echo "  telemetry lines: $TEL ; latency -> $(curl -s "$CONSOLE/api/stats" | grep -o '"latency":{[^}]*}')"
[ "${TEL:-0}" -gt 0 ] && ok "async telemetry emitted (SYNC=false path ran)" || no "no telemetry"

echo "== Phase B: MONITOR attack (expect 200, action log) =="
B=$(curl -s -o /dev/null -w '%{http_code}' "$APP$ATTACK_PATH")
[ "$B" = "200" ] && ok "MONITOR allowed (200)" || no "MONITOR expected 200 got $B"
sleep 1
grep '"event":"ohmyrasp-detection"' "$SHARED/events.jsonl" 2>/dev/null | tail -1 | grep -q '"action":"log"' \
  && ok "MONITOR recorded action=log" || no "MONITOR did not record action=log"

echo "== flip to BLOCK via console API, then attack (expect 500) =="
curl -s -X POST "$CONSOLE/api/control" -H 'Content-Type: application/json' -d '{"mode":"block"}' >/dev/null
sleep 2
C=$(curl -s -o /dev/null -w '%{http_code}' "$APP$ATTACK_PATH")
[ "$C" = "500" ] && ok "BLOCK blocked attack (500) after live mode flip" || no "BLOCK expected 500 got $C"

echo "== flip to OFF via console API, then attack (expect 200, nothing recorded) =="
DET0=$(grep -c '"event":"ohmyrasp-detection"' "$SHARED/events.jsonl" 2>/dev/null || echo 0)
TEL0=$(grep -c '"kind":"telemetry"' "$SHARED/events.jsonl" 2>/dev/null || echo 0)
curl -s -X POST "$CONSOLE/api/control" -H 'Content-Type: application/json' -d '{"mode":"off"}' >/dev/null
sleep 2
O=$(curl -s -o /dev/null -w '%{http_code}' "$APP$ATTACK_PATH")
for i in $(seq 1 10); do curl -s -o /dev/null "$APP$HEALTH_PATH"; done
sleep 2
DET1=$(grep -c '"event":"ohmyrasp-detection"' "$SHARED/events.jsonl" 2>/dev/null || echo 0)
TEL1=$(grep -c '"kind":"telemetry"' "$SHARED/events.jsonl" 2>/dev/null || echo 0)
[ "$O" = "200" ] && ok "OFF allowed (200)" || no "OFF expected 200 got $O"
[ "$DET1" = "$DET0" ] && ok "OFF recorded no detection ($DET0->$DET1)" || no "OFF recorded a detection ($DET0->$DET1)"
[ "$TEL1" = "$TEL0" ] && ok "OFF suppressed telemetry ($TEL0->$TEL1)" || no "OFF still emitted telemetry ($TEL0->$TEL1)"

echo
echo "================  RESULT: PASS=$PASS  FAIL=$FAIL  ================"
[ "$FAIL" = "0" ]
