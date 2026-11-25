#!/usr/bin/env python3
"""Generate Shirudo Java upatch READMEs from the Java agent source and tests.

Writes:
  - deploy/shirudo/README.md
  - deploy/shirudo/ohmyrasp-java8/README.md
  - deploy/shirudo/ohmyrasp-java11/README.md
  - deploy/shirudo/ohmyrasp-java17/README.md
  - deploy/shirudo/ohmyrasp-jdk21/README.md
  - deploy/shirudo/ohmyrasp-jdk25/README.md

Usage:
  python3 deploy/shirudo/gen-readmes.py          # regenerate the top-level and per-package READMEs
  python3 deploy/shirudo/gen-readmes.py --check  # exit non-zero if any file is stale
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

SHIRUDO_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SHIRUDO_DIR.parent.parent
JAVA_AGENT = REPO_ROOT / "java-agent"
SCRIPTS_DIR = JAVA_AGENT / "scripts"
FP_REPORT = JAVA_AGENT / "docs" / "FALSE-POSITIVE-REPORT.md"

sys.path.insert(0, str(SCRIPTS_DIR))
import acceptance_scripts  # noqa: E402
import detector_entry_points  # noqa: E402

JDK_ORDER = ["java7-legacy", "java8", "java11", "java17", "java21", "java6-legacy"]

BACKPORT_TRACKS = [
    {
        "track": "java8",
        "pkg": "ohmyrasp-java8",
        "num": "8",
        "target_jvms": "Java 8",
        "classfile": "<= 52",
        "block_exception": "Java8RaspBlockException",
        "vulhub_jdk": "java8",
    },
    {
        "track": "java11",
        "pkg": "ohmyrasp-java11",
        "num": "11",
        "target_jvms": "Java 11",
        "classfile": "<= 55",
        "block_exception": "Java11RaspBlockException",
        "vulhub_jdk": "java11",
    },
    {
        "track": "java17",
        "pkg": "ohmyrasp-java17",
        "num": "17",
        "target_jvms": "Java 17 and Java 21",
        "classfile": "<= 61",
        "block_exception": "Java17RaspBlockException",
        "vulhub_jdk": "java17",
    },
]

# Category mappings for backport transformers (stem after Java{8,11,17} and before Transformer)
TRANSFORMER_CATEGORY = {
    "Process": "Command Execution & RCE",
    "SparkRest": "Command Execution & RCE",
    "YarnRest": "Command Execution & RCE",
    "ElasticLz4": "Elasticsearch LZ4 Transport (CVE-2026-82303)",
    "Base64": "OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)",
    "Jdbc": "SQL Injection & JDBC",
    "Jndi": "JNDI, Deserialization & XML/XXE",
    "Deserialization": "JNDI, Deserialization & XML/XXE",
    "Fastjson": "JNDI, Deserialization & XML/XXE",
    "Hessian": "JNDI, Deserialization & XML/XXE",
    "JavaBeans": "JNDI, Deserialization & XML/XXE",
    "Xxe": "JNDI, Deserialization & XML/XXE",
    "Servlet": "HTTP Request, Path Confusion, Auth & SSRF",
    "Jwt": "HTTP Request, Path Confusion, Auth & SSRF",
    "Url": "HTTP Request, Path Confusion, Auth & SSRF",
    "File": "File I/O, Uploads & Archive Traversal",
    "MultipartUpload": "File I/O, Uploads & Archive Traversal",
    "Archive": "File I/O, Uploads & Archive Traversal",
    "ScriptEngine": "Expression Engines, Scripting, ClassLoading & JMX",
    "Jexl": "Expression Engines, Scripting, ClassLoading & JMX",
    "El": "Expression Engines, Scripting, ClassLoading & JMX",
    "JavaCompilation": "Expression Engines, Scripting, ClassLoading & JMX",
    "ClassLoader": "Expression Engines, Scripting, ClassLoading & JMX",
    "Jmx": "Expression Engines, Scripting, ClassLoading & JMX",
}

# Category mappings for jdk25 HookModules (stem before HookModule)
MODULE_CATEGORY = {
    "Process": "Command Execution & RCE",
    "ArgumentParser": "Command Execution & RCE",
    "ElasticLz4": "Elasticsearch LZ4 Transport (CVE-2026-82303)",
    "Base64": "OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)",
    "Sql": "SQL Injection & JDBC",
    "Jndi": "JNDI, Deserialization & XML/XXE",
    "ObjectInputStream": "JNDI, Deserialization & XML/XXE",
    "PolymorphicDeserialization": "JNDI, Deserialization & XML/XXE",
    "Hessian": "JNDI, Deserialization & XML/XXE",
    "HttpInvoker": "JNDI, Deserialization & XML/XXE",
    "OpenWire": "JNDI, Deserialization & XML/XXE",
    "RmiRegistry": "JNDI, Deserialization & XML/XXE",
    "Session": "JNDI, Deserialization & XML/XXE",
    "XmlRpc": "JNDI, Deserialization & XML/XXE",
    "JavaBeans": "JNDI, Deserialization & XML/XXE",
    "Xxe": "JNDI, Deserialization & XML/XXE",
    "XmlAttachment": "JNDI, Deserialization & XML/XXE",
    "Servlet": "HTTP Request, Path Confusion, Auth & SSRF",
    "Jwt": "HTTP Request, Path Confusion, Auth & SSRF",
    "Network": "HTTP Request, Path Confusion, Auth & SSRF",
    "File": "File I/O, Uploads & Archive Traversal",
    "MultipartUpload": "File I/O, Uploads & Archive Traversal",
    "Archive": "File I/O, Uploads & Archive Traversal",
    "Expression": "Expression Engines, Scripting, ClassLoading & JMX",
    "JavaCompilation": "Expression Engines, Scripting, ClassLoading & JMX",
    "ClassLoader": "Expression Engines, Scripting, ClassLoading & JMX",
    "Jmx": "Expression Engines, Scripting, ClassLoading & JMX",
    "SpringConfig": "Expression Engines, Scripting, ClassLoading & JMX",
}

CATEGORY_DESCRIPTIONS = {
    "Command Execution & RCE": (
        "Blocks exploit-grade `ProcessBuilder.start` / `Runtime.exec` calls (including "
        "OGNL, SpEL, MVEL, Groovy, JEXL, XStream, deserialization, and scheduler stacks) "
        "and Spark/YARN REST job submissions."
    ),
    "Elasticsearch LZ4 Transport (CVE-2026-82303)": (
        "In block mode, isolates the declared compressed transport block and checks the decoder consumed its exact length."
    ),
    "OpenJDK Base64 AVX-512 Guard (CVE-2026-114938)": (
        "Zero-allocation arithmetic boundary check on `java.util.Base64$Decoder.decode0` "
        "blocking x86-64 AVX-512 tail-underflow inputs (Java2Shell / Java4Shell) before the "
        "native intrinsic runs."
    ),
    "SQL Injection & JDBC": (
        "Detects and blocks structural SQL injection across JDBC `Statement` drivers, "
        "MyBatis `BoundSql` order-by identifiers, GeoServer OGC CQL filters, H2 `INIT` "
        "code execution, Derby SQLJ loading, and MySQL `autoDeserialize` URLs."
    ),
    "JNDI, Deserialization & XML/XXE": (
        "Checks remote naming routes, including JDK JAAS directory lookups, and blocks dangerous "
        "`ObjectInputStream` / RMI / OpenWire / Hessian / Fastjson `autoType` / `1.2.83` "
        "class-resource gadgets, XMLDecoder graphs, and external XML entities (XXE)."
    ),
    "HTTP Request, Path Confusion, Auth & SSRF": (
        "Six-form URI path-confusion decoding (Shiro, GlassFish, Jetty, Spring), weak/default "
        "JWT HMAC secret checks, Shiro default `rememberMe` AES detection, forged internal "
        "identities, and cloud-metadata / loopback-admin / obfuscated-IP SSRF guards."
    ),
    "File I/O, Uploads & Archive Traversal": (
        "Guards sensitive reads (`/etc/passwd`, `/proc/self/environ`, SSH keys), webroot "
        "script writes, ZipSlip archive traversal (`ZipEntry` / 7z), multipart upload path "
        "traversal, and `.gnuplot` command injection."
    ),
    "Expression Engines, Scripting, ClassLoading & JMX": (
        "Inspects Nashorn/Rhino `ScriptEngine`, JEXL, Jakarta/JSP EL, `JavacTool`/Janino "
        "compilation, remote `URLClassLoader`/`RMIClassLoader` codebases, and mutating JMX MBean invocations."
    ),
    "Other / Newly Added": "Additional ASM instrumentation hooks detected in agent sources.",
}

CATEGORY_ORDER = list(CATEGORY_DESCRIPTIONS.keys())


def parse_beefile(pkg: str) -> dict[str, str]:
    text = (SHIRUDO_DIR / pkg / "Beefile").read_text(encoding="utf-8")
    section = ""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if "=" in line:
            k, v = [part.strip() for part in line.split("=", 1)]
            out[f"{section}.{k}"] = v.strip('"\'')
    return {
        "name": out["package.name"],
        "source": out["upatches.source"],
        "tree_id": out["upatches.tree.id"],
    }


def extract_backport(track_info: dict[str, str]) -> dict[str, object]:
    track = track_info["track"]
    num = track_info["num"]
    src_dir = JAVA_AGENT / f"agent-{track}" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent" / track
    agent_text = (src_dir / f"OhMyRaspJava{num}Agent.java").read_text(encoding="utf-8")
    hooks_text = (src_dir / f"Java{num}RaspHooks.java").read_text(encoding="utf-8")
    gradle_text = (JAVA_AGENT / f"agent-{track}" / "build.gradle.kts").read_text(encoding="utf-8")

    transformers = re.findall(rf"new (Java{num}[A-Za-z0-9]+Transformer)\(", agent_text)
    seen: list[str] = []
    for t in transformers:
        if t not in seen:
            seen.append(t)
    algorithms = sorted(set(re.findall(rf'"(java{num}_[a-z0-9_]+)"', hooks_text)))
    baked_keys = sorted(set(re.findall(r"^(standalone|lock_config|mode|control|log|latency_sample)=", gradle_text, re.M)))

    grouped: dict[str, list[str]] = {cat: [] for cat in CATEGORY_ORDER}
    for t in seen:
        stem = t[len(f"Java{num}") : -len("Transformer")]
        cat = TRANSFORMER_CATEGORY.get(stem, "Other / Newly Added")
        grouped[cat].append(t)

    return {
        **track_info,
        "beefile": parse_beefile(track_info["pkg"]),
        "transformers": seen,
        "algorithms": algorithms,
        "grouped": {k: v for k, v in grouped.items() if v},
        "baked_keys": baked_keys,
    }


def extract_jdk25() -> dict[str, object]:
    src_dir = JAVA_AGENT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
    reg_text = (src_dir / "asm" / "HookRegistry.java").read_text(encoding="utf-8")
    gradle_text = (JAVA_AGENT / "agent-jdk25" / "build.gradle.kts").read_text(encoding="utf-8")

    modules = sorted(set(re.findall(r"new ([A-Za-z0-9]+HookModule)\(", reg_text)))
    capabilities = detector_entry_points.capabilities()
    baked_keys = sorted(set(re.findall(r"^(standalone|lock_config|mode|control|log|latency_sample)=", gradle_text, re.M)))

    grouped: dict[str, list[str]] = {cat: [] for cat in CATEGORY_ORDER}
    for m in modules:
        stem = m[: -len("HookModule")]
        cat = MODULE_CATEGORY.get(stem, "Other / Newly Added")
        grouped[cat].append(m)

    return {
        "track": "jdk25",
        "pkg": "ohmyrasp-jdk25",
        "target_jvms": "Java 21 and Java 25",
        "classfile": "<= 65",
        "block_exception": "OhMyRaspBlockException",
        "modules": modules,
        "capabilities": capabilities,
        "grouped": {k: v for k, v in grouped.items() if v},
        "baked_keys": baked_keys,
    }


def extract_vulhub_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    total = 0
    for script in acceptance_scripts.vulhub_scripts():
        total += 1
        stem = acceptance_scripts.legacy_stem(script)
        jdk = next((j for j in JDK_ORDER if stem.endswith("-" + j)), "other")
        counts[jdk] = counts.get(jdk, 0) + 1
    counts["total"] = total
    return counts


def extract_fp_summary() -> tuple[int, int, int, str]:
    text = FP_REPORT.read_text(encoding="utf-8")
    m = re.search(
        r"\|\s*\*\*Overall\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*([0-9.]+%)\*\*\s*\|",
        text,
    )
    cats = len(re.findall(r"^\| [A-Za-z0-9 ]+ \| \d+ \| \d+ \| [0-9.]+% \|$", text, re.M))
    if not m:
        return 0, 0, cats, "n/a"
    return int(m.group(1)), int(m.group(2)), cats, m.group(3)


def render_top_readme(
    backports: list[dict[str, object]],
    jdk25: dict[str, object],
    primary_packages: list[dict[str, str]],
    vulhub: dict[str, int],
    fp: tuple[int, int, int, str],
) -> str:
    fp_inputs, fp_hits, fp_cats, fp_rate = fp
    lines: list[str] = []
    w = lines.append

    w("# OhMyRASP Shirudo Java Upatch Packages")
    w("")
    w("> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources and test suites.")
    w("> Re-run after changing hooks, transformers, or detectors; `--check` fails CI when stale.")
    w("")
    w("Packages OhMyRASP's standalone, daemonless Java runtime self-protection agents as")
    w("[shirudo](https://github.com/shirudo-dev/shirudo) Java upatches (`.bee` packages and")
    w("signed `.upatch` artifacts).")
    w("")
    w("Pre-built staged JARs and the full `deploy/shirudo/` bundle")
    w("(`ohmyrasp-shirudo-upatches-<version>.tar.gz`) are published on")
    w("[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases), ready to sign")
    w("with `shirudo bpm build`.")
    w("")
    w("## Packages")
    w("")
    w("| Package | Target JVMs | Upatch / JAR | Instrumentation | Detection Scope | Vulhub Replay |")
    w("|---|---|---|---|---|---|")
    for b in backports:
        bf = b["beefile"]
        assert isinstance(bf, dict)
        vcount = vulhub.get(str(b["vulhub_jdk"]), 0)
        note = f"{vcount} ({b['vulhub_jdk']})"
        if b["track"] == "java17":
            note = f"{vcount} (java17) + {vulhub.get('java21', 0)} (java21)"
        w(
            f"| `{bf['name']}` | {b['target_jvms']} (classfile `{b['classfile']}`) | "
            f"`{bf['source']}` | {len(b['transformers'])} ASM transformers | "
            f"{len(b['algorithms'])} algorithms | {note} |"
        )
    for bf in primary_packages:
        w(
            f"| `{bf['name']}` | {jdk25['target_jvms']} (classfile `{jdk25['classfile']}`) | "
            f"`{bf['source']}` | {len(jdk25['modules'])} ASM hook modules | "
            f"{len(jdk25['capabilities'])} `detect*` capabilities | {vulhub['total']} total scenarios across 6 JDK lines |"
        )
    w("")
    w("Choose one primary package per JVM. The JDK 21 and 25 names contain the same agent bytecode.")
    w("For JDK 21, extract `ohmyrasp-jdk21-shirudo.tar.gz` to sign the staged package with your operator keys.")
    w("")
    w(
        f"Benign-traffic precision across the curated engine corpus: **{fp_hits} / {fp_inputs}** "
        f"false positives across **{fp_cats}** categories ({fp_rate}; see "
        "[FALSE-POSITIVE-REPORT.md](../../java-agent/docs/FALSE-POSITIVE-REPORT.md))."
    )
    w("")
    w("## Security Protections Included")
    w("")
    w("Each package injects ASM bytecode hooks at JVM class-load / retransform time across the following attack surfaces:")
    w("")
    w("| Security Category | What It Inspects & Blocks | Java 8 / 11 / 17 Transformers | JDK 21/25 Hook Modules |")
    w("|---|---|---|---|")
    sample_bp = backports[0]["grouped"]
    assert isinstance(sample_bp, dict)
    jdk25_grp = jdk25["grouped"]
    assert isinstance(jdk25_grp, dict)
    for cat in CATEGORY_ORDER:
        bp_items = sample_bp.get(cat, [])
        j25_items = jdk25_grp.get(cat, [])
        if not bp_items and not j25_items:
            continue
        bp_str = ", ".join(f"`{t.replace('Java8', 'Java*')}`" for t in bp_items) if bp_items else "-"
        j25_str = ", ".join(f"`{m}`" for m in j25_items) if j25_items else "-"
        w(f"| **{cat}** | {CATEGORY_DESCRIPTIONS[cat]} | {bp_str} | {j25_str} |")
    w("")
    w("### Blocking Semantics Across Tracks")
    w("")
    w("- **`ohmyrasp-java8`, `ohmyrasp-java11`, `ohmyrasp-java17`**: With baked-in `mode=block`, exploit-grade sink detections (command execution, sensitive file reads/script writes, remote JNDI, deserialization gadgets, SQLi/JDBC, XXE, SSRF, Base64 CVE-2026-114938, and servlet path/JWT/cookie checks) throw `Java*RaspBlockException` both inside HTTP requests and in standalone JVMs.")
    w("- **`ohmyrasp-jdk21`, `ohmyrasp-jdk25`** use the evidence available at the hook and the active policy to decide whether to block. Some rules can enforce outside an HTTP request, including class checks on an XML-RPC object stream. [Detection policies](../../docs/detection.md#deserialization-defenses)")
    w("")
    w("## Standalone Profile (`META-INF/ohmyrasp-shirudo.properties`)")
    w("")
    w("Each shirudo upatch JAR embeds `META-INF/ohmyrasp-shirudo.properties` so it runs without a host daemon, control file, or spool rotation:")
    w("")
    w("- `standalone=true`: turns cloud upload off (`cloud_direct` forced off) and makes `none` the default control path.")
    w("- `lock_config=true`: `standalone`, `mode` and `control` come only from this baked file; `/tmp/ohmyrasp-control.json`, `OHMYRASP_MODE=off` and `OHMYRASP_CONTROL` are ignored. `log` and `latency_sample` stay overridable. The `ohmyrasp-java8`, `ohmyrasp-java11` and `ohmyrasp-java17` JARs read the file only from their own JAR; the primary-agent packages (`ohmyrasp-jdk21`, `ohmyrasp-jdk25`) can read a same-named file from the application class path instead.")
    w("- `mode=block`: enables blocking immediately at JVM startup (use `--mode monitor` when building for observe-only rollout).")
    w("- `control=none`: starts zero background control-poller threads.")
    w("- `log=stderr`: writes structured JSON detection events directly to `stderr` with zero file-writer threads and no `/tmp/ohmyrasp-events.jsonl`, unless a log override names a file at start-up.")
    w("- `latency_sample=0`: suppresses benign `hook_latency` telemetry lines.")
    w("")
    w("## Build")
    w("")
    w("Build and sign all `.bee` packages into the current working directory:")
    w("")
    w("```sh")
    w('./deploy/shirudo/build-all.sh "<version>" --keys-dir "<keys>"')
    w("```")
    w("")
    w("Build a single package (for example `ohmyrasp-java17`):")
    w("")
    w("```sh")
    w('./deploy/shirudo/ohmyrasp-java17/build.sh "<version>" --keys-dir "<keys>"')
    w("```")
    w("")
    w("Stage only the `.jar` artifacts without invoking `shirudo bpm build` (for example before verification or smoke tests without operator keys):")
    w("")
    w("```sh")
    w("./deploy/shirudo/build-all.sh --jar-only")
    w("```")
    w("")
    w("Both `build.sh` and `build-all.sh` accept `--mode block|monitor` (default: `block`) and honor `SHIRUDO_BIN` when `shirudo` is not on `PATH`. If `gradle` is not installed locally, the build scripts run the Gradle Docker image pinned in each `build.sh` under the caller's UID/GID.")
    w("")
    w("## Load, Unload, and How `shirudo` Attaches the Agent")
    w("")
    w("Install a built `.bee` package (or load a signed `.upatch` directly) on a shirudo target:")
    w("")
    w("```sh")
    w("sudo shirudo bpm install <repository>/ohmyrasp-java17")
    w("# or load a standalone signed artifact:")
    w("sudo shirudo upatch load ohmyrasp-java17.upatch")
    w("```")
    w("")
    w("Unload on the target:")
    w("")
    w("```sh")
    w("sudo shirudo bpm uninstall ohmyrasp-java17")
    w("# or unload a standalone signed artifact:")
    w("sudo shirudo upatch unload ohmyrasp-java17.unload.upatch")
    w("```")
    w("")
    w("When a Java upatch `<name>` is loaded, `shirudo`:")
    w("")
    w("1. Verifies the ML-DSA-87 signature against the target's sealed `.bpf` keyring, extends the TPM2 measurement register with a `java_load` event, and seals the signed JAR at `/run/shirudo-java/<name>.jar` (mode `0644`).")
    w("2. Writes `/run/environment.d/shirudo.conf` with `-javaagent:/run/shirudo-java/<name>.jar` for each loaded Java upatch in name order, appended to `JAVA_TOOL_OPTIONS`.")
    w("")
    w("On `unload`, `shirudo` measures a `java_unload` event, replaces `/run/shirudo-java/<name>.jar` with a no-op stub JAR (so JVMs started from an already-running systemd user manager do not abort on a missing `-javaagent` path), and updates `/run/environment.d/shirudo.conf`.")
    w("")
    w("## Java 8 `JAVA_TOOL_OPTIONS` Limit")
    w("")
    w("OpenJDK 8 truncates `JAVA_TOOL_OPTIONS` at **1024 bytes** and **64 options** without reporting an error (JDK-8288483), silently dropping trailing options. Package and upatch names are deliberately kept short (`ohmyrasp-java8`, producing `-javaagent:/run/shirudo-java/ohmyrasp-java8.jar`, 47 bytes), and `ohmyrasp-java8.jar` omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path directly.")
    w("")
    w("## Containers and System Services")
    w("")
    w("`systemd` user managers read `/run/environment.d/shirudo.conf` at startup and pass `JAVA_TOOL_OPTIONS` to JVMs they launch afterwards.")
    w("")
    w("- **Containers, system services, and direct logins** do not inherit user-manager `environment.d` files. Pass `-javaagent:/run/shirudo-java/<name>.jar` explicitly on the unit or container (for example via `JAVA_TOOL_OPTIONS` with the sealed JAR bind-mounted read-only).")
    w("- **Already-running JVMs** only read `JAVA_TOOL_OPTIONS` at process start and must be restarted to pick up a newly loaded or unloaded upatch.")
    w("")
    w("## Security Boundary")
    w("")
    w("A Java upatch is **an application-level mitigation inside the JVM**, not a kernel security boundary:")
    w("")
    w("- `shirudo`'s seal protects `/run/shirudo-java/<name>.jar` from tampering by unprivileged tasks, while `/run/environment.d/shirudo.conf` is not sealed.")
    w("- `root` or the user launching a JVM can override `JAVA_TOOL_OPTIONS` or start a JVM without `-javaagent`. Use BPF upatches for policies that `root` must not bypass.")
    w("- A Java agent cannot query or call BPF upatches because shirudo's BPF LSM denies `BPF_OBJ_GET` and `BPF_PROG_TEST_RUN` to all tasks except `shirudo`.")
    w("")
    w("## Verification and Smoke Tests")
    w("")
    w("Validate Beefile syntax/limits, staged JAR manifests/properties, and README freshness:")
    w("")
    w("```sh")
    w("python3 deploy/shirudo/gen-readmes.py --check")
    w("./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only")
    w("./deploy/shirudo/verify-shirudo-upatch.sh")
    w("```")
    w("")
    w("Run the real-JVM Docker integration suite across Temurin 8, 11, 17, 21, and 25:")
    w("")
    w("```sh")
    w("./deploy/shirudo/smoke-test.sh")
    w("```")
    return "\n".join(lines) + "\n"


def render_backport_readme(b: dict[str, object], vulhub: dict[str, int]) -> str:
    bf = b["beefile"]
    assert isinstance(bf, dict)
    pkg = bf["name"]
    jar = bf["source"]
    lines: list[str] = []
    w = lines.append

    w(f"# {pkg}")
    w("")
    w("> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.")
    w("")
    w(
        f"The `{pkg}` package installs the `{pkg}` Java upatch: a standalone, "
        f"daemonless OhMyRASP runtime self-protection agent targeting **{b['target_jvms']}** "
        f"JVMs (classfile version `{b['classfile']}`). It covers **{len(b['transformers'])} ASM "
        f"transformer families** and **{len(b['algorithms'])} detection algorithms**, validated "
        f"against **{vulhub.get(str(b['vulhub_jdk']), 0)}** real Vulhub scenarios on `{b['vulhub_jdk']}`"
        + (
            f" plus **{vulhub.get('java21', 0)}** on `java21`."
            if b["track"] == "java17"
            else "."
        )
    )
    w("")
    w("## Security Coverage")
    w("")
    w("| Category | Protection Scope | ASM Transformers |")
    w("|---|---|---|")
    grouped = b["grouped"]
    assert isinstance(grouped, dict)
    for cat in CATEGORY_ORDER:
        items = grouped.get(cat, [])
        if not items:
            continue
        t_list = ", ".join(f"`{t}`" for t in items)
        w(f"| **{cat}** | {CATEGORY_DESCRIPTIONS[cat]} | {t_list} |")
    w("")
    w("<details><summary>All detection algorithm IDs (" + str(len(b["algorithms"])) + ")</summary>")
    w("")
    for algo in b["algorithms"]:
        w(f"- `{algo}`")
    w("")
    w("</details>")
    w("")
    w("## Runtime Behavior")
    w("")
    w(
        "- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, "
        "`control=none` and `log=stderr`. No control-file poller is started, and "
        "`/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored. The baked settings "
        "are read only from this JAR: a same-named `META-INF/ohmyrasp-shirudo.properties` "
        "elsewhere on the class path is ignored. The runtime starts while the agent loads, "
        "before any hook is installed, and no background event-writer thread is started "
        "unless a log override names a file at start-up."
    )
    w(
        f"- **Blocking enforcement**: Built with `mode=block`; exploit detections throw "
        f"`{b['block_exception']}` immediately at the sink (including standalone non-HTTP "
        "calls such as malicious `InitialContext.lookup`, `/etc/passwd` reads, `Statement` "
        "SQLi, deserialization gadgets, and CVE-2026-114938 Base64 tail-underflow)."
    )
    w(
        "- **Logging**: Emits structured JSON detection events directly to `stderr` "
        "(`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output "
        "and no `hook_latency` telemetry."
    )
    w("")
    w("## Deployment and Limits")
    w("")
    w(
        f"- `shirudo` seals the signed JAR at `/run/shirudo-java/{jar}` and appends "
        f"`-javaagent:/run/shirudo-java/{jar}` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`."
    )
    if b["track"] == "java8":
        w(
            "- **Java 8 `JAVA_TOOL_OPTIONS` limit**: OpenJDK 8 truncates `JAVA_TOOL_OPTIONS` at "
            "1024 bytes and 64 options (JDK-8288483); keep agents few and options short. This JAR "
            "also omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed "
            "`/run/shirudo-java/` path cleanly."
        )
    w(
        f"- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; "
        f"system services and containers must pass `-javaagent:/run/shirudo-java/{jar}` explicitly."
    )
    w(
        "- A Java agent is an application-level mitigation inside the JVM, not a kernel security "
        "boundary against `root` or the JVM-launching user."
    )
    w("- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.")
    return "\n".join(lines) + "\n"


def render_primary_readme(jdk25: dict[str, object], bf: dict[str, str], vulhub: dict[str, int]) -> str:
    pkg = bf["name"]
    jar = bf["source"]
    lines: list[str] = []
    w = lines.append

    w(f"# {pkg}")
    w("")
    w("> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.")
    w("")
    w(
        f"The `{pkg}` package installs the `{pkg}` Java upatch: a standalone, daemonless "
        f"OhMyRASP runtime self-protection agent targeting **{jdk25['target_jvms']}** JVMs "
        f"(classfile version `{jdk25['classfile']}`). It registers **{len(jdk25['modules'])} "
        f"ASM hook modules** and **{len(jdk25['capabilities'])} detector capabilities**, "
        f"backed by **{vulhub['total']}** end-to-end Vulhub acceptance scenarios."
    )
    w("")
    w("## Security Coverage")
    w("")
    w("| Category | Protection Scope | ASM Hook Modules |")
    w("|---|---|---|")
    grouped = jdk25["grouped"]
    assert isinstance(grouped, dict)
    for cat in CATEGORY_ORDER:
        items = grouped.get(cat, [])
        if not items:
            continue
        m_list = ", ".join(f"`{m}`" for m in items)
        w(f"| **{cat}** | {CATEGORY_DESCRIPTIONS[cat]} | {m_list} |")
    w("")
    w("<details><summary>All detector capabilities (" + str(len(jdk25["capabilities"])) + ")</summary>")
    w("")
    for cap in jdk25["capabilities"]:
        w(f"- `detect{cap}`")
    w("")
    w("</details>")
    w("")
    w("## Runtime Behavior")
    w("")
    w(
        "- **Standalone and daemonless**: Built with `standalone=true`, `lock_config=true`, "
        "`control=none` and `log=stderr`. No control-file poller is started, `cloud_direct` "
        "is forced off, and `/tmp/ohmyrasp-control.json` or `OHMYRASP_MODE=off` is ignored. "
        "No background event-writer thread is started unless a log override names a file "
        "at start-up."
    )
    w(
        "- **Blocking enforcement** uses `mode=block`. Enforcement outside an HTTP request depends on "
        "the hook evidence and the active rule. Monitor decisions emit structured events to `stderr`. "
        "[Detection policies](../../../docs/detection.md#deserialization-defenses)"
    )
    w(
        "- **Logging**: Emits structured JSON detection events directly to `stderr` "
        "(`log=stderr`, `latency_sample=0`) with no `/tmp/ohmyrasp-events.jsonl` file output "
        "and no `hook_latency` telemetry."
    )
    w("")
    w("## Deployment and Limits")
    w("")
    w(
        f"- `shirudo` seals the signed JAR at `/run/shirudo-java/{jar}` and appends "
        f"`-javaagent:/run/shirudo-java/{jar}` to `JAVA_TOOL_OPTIONS` in `/run/environment.d/shirudo.conf`."
    )
    w(
        f"- Only JVMs started by a systemd user manager after load inherit `/run/environment.d/shirudo.conf`; "
        f"system services and containers must pass `-javaagent:/run/shirudo-java/{jar}` explicitly."
    )
    w(
        "- A Java agent is an application-level mitigation inside the JVM, not a kernel security "
        "boundary against `root` or the JVM-launching user."
    )
    w("- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if any generated README is stale")
    args = parser.parse_args()

    backports = [extract_backport(t) for t in BACKPORT_TRACKS]
    jdk25 = extract_jdk25()
    primary_packages = [parse_beefile(name) for name in ("ohmyrasp-jdk21", "ohmyrasp-jdk25")]
    vulhub = extract_vulhub_counts()
    fp = extract_fp_summary()

    outputs: dict[pathlib.Path, str] = {
        SHIRUDO_DIR / "README.md": render_top_readme(backports, jdk25, primary_packages, vulhub, fp),
    }
    for bf in primary_packages:
        outputs[SHIRUDO_DIR / bf["name"] / "README.md"] = render_primary_readme(jdk25, bf, vulhub)
    for b in backports:
        outputs[SHIRUDO_DIR / str(b["pkg"]) / "README.md"] = render_backport_readme(b, vulhub)

    stale: list[pathlib.Path] = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if args.check:
            if current != content:
                stale.append(path)
        else:
            if current != content:
                path.write_text(content, encoding="utf-8")
                print(f"wrote {path.relative_to(REPO_ROOT)}")
            else:
                print(f"up-to-date {path.relative_to(REPO_ROOT)}")

    if stale:
        for path in stale:
            print(f"STALE: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
        print("Run: python3 deploy/shirudo/gen-readmes.py", file=sys.stderr)
        return 1
    if args.check:
        print(f"OK readmes: {len(outputs)} files up-to-date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
