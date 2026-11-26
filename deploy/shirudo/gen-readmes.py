#!/usr/bin/env python3
"""Generate Shirudo Java upatch READMEs from the Java agent source and tests.

Writes:
  - deploy/shirudo/README.md
  - deploy/shirudo/ohmyrasp/README.md
  - the `fixes` line of deploy/shirudo/ohmyrasp/Beefile, from deploy/shirudo/fixes.toml
  - deploy/shirudo/ohmyrasp-java8/README.md
  - deploy/shirudo/ohmyrasp-java11/README.md
  - deploy/shirudo/ohmyrasp-java17/README.md
  - deploy/shirudo/ohmyrasp-jdk21/README.md
  - deploy/shirudo/ohmyrasp-jdk25/README.md

Usage:
  python3 deploy/shirudo/gen-readmes.py          # regenerate the top-level and per-package READMEs
  python3 deploy/shirudo/gen-readmes.py --check  # exit non-zero if any file is stale, or an advisory in
                                                 # fixes.toml lacks the evidence fixes_check.py asks for
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
import fixes_check  # noqa: E402  (deploy/shirudo/, which is on sys.path as this script's directory)

UNIVERSAL_PKG = "ohmyrasp"
PACKAGE_ORDER = (UNIVERSAL_PKG, "ohmyrasp-java8", "ohmyrasp-java11", "ohmyrasp-java17", "ohmyrasp-jdk21", "ohmyrasp-jdk25")
JAVA8_OPTIONS_LIMIT = 1024  # bytes of JAVA_TOOL_OPTIONS an OpenJDK 8 reads (JDK-8288483)
REPO_URL = "https://github.com/xuing/oh-my-rasp"

JDK_ORDER = ["java7-legacy", "java8", "java11", "java17", "java21", "java6-legacy"]

BACKPORT_TRACKS = [
    {
        "track": "java8",
        "pkg": "ohmyrasp-java8",
        "num": "8",
        "starts_on": "Java 8 only",
        "target_jvms": "Java 8",
        "classfile": "<= 52",
        "block_exception": "Java8RaspBlockException",
        "vulhub_jdk": "java8",
    },
    {
        "track": "java11",
        "pkg": "ohmyrasp-java11",
        "num": "11",
        "starts_on": "Java 11 and later",
        "target_jvms": "Java 11",
        "classfile": "<= 55",
        "block_exception": "Java11RaspBlockException",
        "vulhub_jdk": "java11",
    },
    {
        "track": "java17",
        "pkg": "ohmyrasp-java17",
        "num": "17",
        "starts_on": "Java 17 and later",
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
        "starts_on": "Java 21 and later",
        "target_jvms": "Java 21 and Java 25",
        "classfile": "<= 65",
        "block_exception": "OhMyRaspBlockException",
        "modules": modules,
        "capabilities": capabilities,
        "grouped": {k: v for k, v in grouped.items() if v},
        "baked_keys": baked_keys,
    }


def extract_vulhub_counts() -> dict[str, int]:
    """Vulhub scripts that run the exploit on a JVM an agent line supports, by JDK line.

    A legacy-JVM script (Java 6 or 7, where the agent skips and the JVM runs unprotected) or a setup/licence
    boundary script shows no block, so no count here includes one (acceptance_scripts.is_boundary).
    """
    counts: dict[str, int] = {}
    total = 0
    for script in acceptance_scripts.vulhub_scripts():
        if acceptance_scripts.is_boundary(script):
            continue
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


def option(jar: str) -> str:
    return f"-javaagent:/run/shirudo-java/{jar}"


def java8_options_bytes() -> tuple[int, int]:
    """(bytes of JAVA_TOOL_OPTIONS when every OhMyRASP package is loaded, bytes of the longest single option)."""
    options = [option(f"{pkg}.jar") for pkg in PACKAGE_ORDER]
    return len(" ".join(options)), max(len(o) for o in options)


def start_lines(backports: list[dict[str, object]]) -> list[tuple[str, str]]:
    """(JVM, the first thing the line writes to stderr), read from the line's source so the README cannot drift."""
    rows: list[tuple[str, str]] = []
    for b in backports:
        track, num = str(b["track"]), str(b["num"])
        src = JAVA_AGENT / f"agent-{track}" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent" / track
        text = (src / f"OhMyRaspJava{num}Agent.java").read_text(encoding="utf-8")
        event = f"ohmyrasp-java{num}-agent-start"
        if event not in text:
            raise SystemExit(f"gen-readmes: {track} no longer writes the `{event}` start event; update the start lines")
        rows.append((f"Java {num}", f'{{"event":"{event}","mode":"premain", ...}}'))
    primary = (JAVA_AGENT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
               / "BootstrapAgent.java").read_text(encoding="utf-8")
    marker = "[OHMYRASP] agent started with ASM transformer, standalone="
    if marker not in primary:
        raise SystemExit("gen-readmes: the primary line no longer writes its start line; update the start lines")
    rows.append(("Java 21 and 25", "[OHMYRASP] agent started with ASM transformer, standalone=true, mode=block, args="))
    return rows


def render_active_section(w, rows: list[tuple[str, str]], level: str) -> None:
    w(f"{level} Check that it is active")
    w("")
    w("A protected JVM writes one line to its standard error when it starts, before the application runs. "
      "The line names the Java line that started. The Java 21 and later line also shows the baked mode, "
      "`block` here and `monitor` in a monitor build:")
    w("")
    w("| JVM | First line on stderr |")
    w("|---|---|")
    for jvm, line in rows:
        w(f"| {jvm} | `{line}` |")
    w("")
    w("JVMs that start a Java agent with an appended bootstrap path may also print "
      "`OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes because bootstrap "
      "classpath has been appended`. It is the JVM's notice that class-data sharing is limited, not an error.")
    w("")
    w("A JVM that was already running when the package was loaded shows none of this: it has to restart. "
      "A JVM that a systemd user manager starts also needs a manager that has read the change. The manager reads "
      "`/run/environment.d/shirudo.conf` when it starts and when it reloads, so a manager that started before the "
      "upatch was loaded (or unloaded) still passes the old options, and a restarted JVM starts without the agent. "
      "Run `systemctl --user daemon-reload` as the JVM's user, check with `systemctl --user show-environment | "
      "grep JAVA_TOOL_OPTIONS` that the manager now names the agent, then restart the JVM.")
    w("")
    w("To see whether a running JVM has the agent, look for the start line in its log, or ask the JVM: "
      "`jcmd <pid> VM.system_properties | grep ohmyrasp.agent.line` prints `ohmyrasp.agent.line=<line>`, one of "
      "`primary`, `java17`, `java11` and `java8`, when a line started, and prints nothing when none did.")
    w("")
    w("A JVM whose line is not started says why in one JSON line instead:")
    w("")
    w("- `{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"unsupported-java\", ...}`: this JAR holds no line that "
      "fits the JVM's Java version (a per-line JAR on a Java it does not cover, or any JAR on Java 9 or 10). "
      "This JAR protects nothing; the JVM and the application start.")
    w("- `{\"event\":\"ohmyrasp-agent-skipped\",\"reason\":\"already-active\", ...}`: another OhMyRASP JAR started a "
      "line first. The JVM is protected.")
    w("- `{\"event\":\"ohmyrasp-agent-start-failed\", ...}`: the line threw while starting. Protection is inactive "
      "or incomplete, and the JVM still starts.")
    w("")
    w("Detections are JSON objects, one per line, on the JVM's standard error "
      "(`\"event\":\"ohmyrasp-detection\"`, with the hook, the rule in `algorithm`, and `action`: `block` or "
      "`monitor`). Nothing is written to a file. Read them where the JVM's stderr goes: `journalctl -u <unit>` for a "
      "systemd unit, `docker logs <container>` for a container.")
    w("")


def render_top_readme(
    backports: list[dict[str, object]],
    jdk25: dict[str, object],
    primary_packages: list[dict[str, str]],
    universal: dict[str, str],
    vulhub: dict[str, int],
    fp: tuple[int, int, int, str],
) -> str:
    fp_inputs, fp_hits, fp_cats, fp_rate = fp
    all_bytes, _ = java8_options_bytes()
    lines: list[str] = []
    w = lines.append

    w("# OhMyRASP Shirudo Java Upatch Packages")
    w("")
    w("> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources and test suites.")
    w("> Re-run after changing hooks, transformers, or detectors; `--check` fails CI when stale.")
    w("")
    w("Packages OhMyRASP's standalone, daemonless Java runtime self-protection agent as")
    w("[shirudo](https://github.com/shirudo-dev/shirudo) Java upatches (`.bee` packages and")
    w("signed `.upatch` artifacts).")
    w("")
    w("Pre-built staged JARs and the full `deploy/shirudo/` bundle")
    w("(`ohmyrasp-shirudo-upatches-<version>.tar.gz`) are published on")
    w("[GitHub Releases](https://github.com/xuing/oh-my-rasp/releases), ready to sign")
    w("with `shirudo bpm build`.")
    w("")
    w("## Quick start")
    w("")
    w(f"Install one package, `{UNIVERSAL_PKG}`. Every JVM on the host, from Java 8 to Java 25, gets the agent line "
      "that fits its Java version:")
    w("")
    w("```sh")
    w(f"sudo shirudo bpm install <repository>/{UNIVERSAL_PKG}")
    w("```")
    w("")
    w(f"`{UNIVERSAL_PKG}.jar` holds every line and a launcher. When a JVM loads it through `JAVA_TOOL_OPTIONS`, the "
      "launcher reads the JVM's Java version and starts the first line, in the order primary (Java 21 and later), "
      "Java 17, Java 11, Java 8, whose range contains it. The launcher never stops the JVM: a JVM that fits no line "
      "(Java 9 and 10 have none) writes one `ohmyrasp-agent-skipped` JSON line to stderr and the application starts "
      "without protection. A host with Java 8, 11, 17 and 21 applications needs no per-version setup, and installing "
      "the package stops none of them from starting.")
    w("")
    w(f"A second OhMyRASP package on the same host is harmless. One line starts per JVM, the first JAR in "
      f"`JAVA_TOOL_OPTIONS` wins (shirudo lists the agents in name order, so `{UNIVERSAL_PKG}` comes before "
      f"`ohmyrasp-java8`), and each later JAR writes `\"reason\":\"already-active\"` and does nothing more.")
    w("")
    w("## Packages")
    w("")
    w("| Package | Starts on | Upatch / JAR | Instrumentation | Detection Scope | Vulhub Replay |")
    w("|---|---|---|---|---|---|")
    w(
        f"| `{universal['name']}` | Java 8 to 25, the line that fits | `{universal['source']}` | "
        f"every line below | every line below | {vulhub['total']} Vulhub scripts on supported JVMs |"
    )
    for b in backports:
        bf = b["beefile"]
        assert isinstance(bf, dict)
        vcount = vulhub.get(str(b["vulhub_jdk"]), 0)
        note = f"{vcount} ({b['vulhub_jdk']})"
        if b["track"] == "java17":
            note = f"{vcount} (java17) + {vulhub.get('java21', 0)} (java21)"
        w(
            f"| `{bf['name']}` | {b['starts_on']} (classfile `{b['classfile']}`) | "
            f"`{bf['source']}` | {len(b['transformers'])} ASM transformers | "
            f"{len(b['algorithms'])} algorithms | {note} |"
        )
    for bf in primary_packages:
        w(
            f"| `{bf['name']}` | {jdk25['starts_on']} (classfile `{jdk25['classfile']}`) | "
            f"`{bf['source']}` | {len(jdk25['modules'])} ASM hook modules | "
            f"{len(jdk25['capabilities'])} `detect*` capabilities | {vulhub['total']} Vulhub scripts on supported JVMs |"
        )
    w("")
    w("## Which package to install")
    w("")
    w(f"- **`{UNIVERSAL_PKG}`** is the default for any host, and the only choice for a host with more than one Java "
      "version. A JVM gets the line that fits it, so a Java 21 JVM gets the primary line and a Java 17 JVM the "
      "Java 17 line.")
    w("- **A per-line package** is for a host pinned to one Java version, or for an operator who wants only one line's "
      "JAR to sign. It holds that line only and starts it on every Java the line supports: `ohmyrasp-java11` starts "
      "the Java 11 line on a Java 17 or 21 JVM too, where `ohmyrasp` would start the Java 17 or the primary line. On a "
      "Java the line does not support it writes the `ohmyrasp-agent-skipped` line and the JVM starts unprotected. "
      "The names `ohmyrasp-jdk21` and `ohmyrasp-jdk25` hold the same agent bytecode.")
    w("- **Mixed installs** are safe. Each JVM starts one line, whichever JAR comes first and fits.")
    w("")
    w("For JDK 21, extract `ohmyrasp-jdk21-shirudo.tar.gz` to sign the staged package with your operator keys.")
    w("")
    w(
        f"Benign-traffic precision across the curated engine corpus: **{fp_hits} / {fp_inputs}** "
        f"false positives across **{fp_cats}** categories ({fp_rate}; see "
        "[FALSE-POSITIVE-REPORT.md](../../java-agent/docs/FALSE-POSITIVE-REPORT.md))."
    )
    w("")
    render_active_section(w, start_lines(backports), "##")
    w("## Advisories the universal package lists")
    w("")
    w(f"`{UNIVERSAL_PKG}/Beefile` sets `fixes` in its `[upatches.tree]` entry, which shirudo's backend reads to show "
      "which loaded upatch covers an advisory a node is exposed to. "
      "The list means that the agent blocks the tested exploit path of that advisory inside the JVM; it does not "
      "patch the vulnerable library. It describes the block build: a monitor build only observes, so `build.sh --mode "
      "monitor` packages it from a Beefile without `fixes`, and `verify-shirudo-upatch.sh` checks that the baked mode "
      "and the Beefile agree. "
      "It is written from [fixes.toml](fixes.toml), which names for each advisory the Vulhub acceptance script that "
      "shows it, and `gen-readmes.py --check` fails when the list, the script or the evidence ledger disagree. "
      "`replay-fixes.sh` runs those scripts against the universal JAR; `fixes.toml` records the date of the last "
      "replay of each entry. "
      f"The per-line packages list none. See [{UNIVERSAL_PKG}/README.md]({UNIVERSAL_PKG}/README.md) for the list.")
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
    w(f"- **`{UNIVERSAL_PKG}`** blocks as the line it starts does: the Java 8, 11 and 17 lines on those JVMs, the primary line on Java 21 and later.")
    w("- **`ohmyrasp-java8`, `ohmyrasp-java11`, `ohmyrasp-java17`**: With baked-in `mode=block`, exploit-grade sink detections (command execution, sensitive file reads/script writes, remote JNDI, deserialization gadgets, SQLi/JDBC, XXE, SSRF, Base64 CVE-2026-114938, and servlet path/JWT/cookie checks) throw `Java*RaspBlockException` both inside HTTP requests and in standalone JVMs.")
    w("- **`ohmyrasp-jdk21`, `ohmyrasp-jdk25`** use the evidence available at the hook and the active policy to decide whether to block. Some rules can enforce outside an HTTP request, including class checks on an XML-RPC object stream. [Detection policies](../../docs/detection.md#deserialization-defenses)")
    w("")
    w("## Standalone Profile (`META-INF/ohmyrasp-shirudo.properties`)")
    w("")
    w("Each shirudo upatch JAR, the universal one included, embeds `META-INF/ohmyrasp-shirudo.properties` so it runs without a host daemon, control file, or spool rotation:")
    w("")
    w("- `standalone=true`: turns cloud upload off (`cloud_direct` forced off) and control-file polling off, whatever control path is set.")
    w("- `lock_config=true`: `standalone`, `mode` and `control` come only from this baked file; `OHMYRASP_MODE=off` and `OHMYRASP_CONTROL` are ignored, and a baked file without `control` polls no control file, not even the default `/tmp/ohmyrasp-control.json`. A locked JAR that is not standalone polls a baked control path, the default one included. `log` and `latency_sample` stay overridable. Every package reads the file only from its own JAR; a same-named file on the application class path is ignored. When two OhMyRASP JARs hold the same line, that line's classes and the baked file it reads come from the first of them on the class path.")
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
    w(f"Build a single package (for example `{UNIVERSAL_PKG}`):")
    w("")
    w("```sh")
    w(f'./deploy/shirudo/{UNIVERSAL_PKG}/build.sh "<version>" --keys-dir "<keys>"')
    w("```")
    w("")
    w("Stage only the `.jar` artifacts without invoking `shirudo bpm build` (for example before verification or smoke tests without operator keys):")
    w("")
    w("```sh")
    w("./deploy/shirudo/build-all.sh --jar-only")
    w("```")
    w("")
    w("Both `build.sh` and `build-all.sh` accept `--mode block|monitor` (default: `block`) and honor `SHIRUDO_BIN` when `shirudo` is not on `PATH`. If `gradle` is not installed locally, the build scripts run the Gradle Docker image that `java-agent/Dockerfile` pins, under the caller's UID/GID.")
    w("")
    w("## Load, Unload, and How `shirudo` Attaches the Agent")
    w("")
    w("Install a built `.bee` package (or load a signed `.upatch` directly) on a shirudo target:")
    w("")
    w("```sh")
    w(f"sudo shirudo bpm install <repository>/{UNIVERSAL_PKG}")
    w("# or load a standalone signed artifact:")
    w(f"sudo shirudo upatch load {UNIVERSAL_PKG}.upatch")
    w("```")
    w("")
    w("Unload on the target:")
    w("")
    w("```sh")
    w(f"sudo shirudo bpm uninstall {UNIVERSAL_PKG}")
    w("# or unload a standalone signed artifact:")
    w(f"sudo shirudo upatch unload {UNIVERSAL_PKG}.unload.upatch")
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
    w(f"OpenJDK 8 does not honor a `JAVA_TOOL_OPTIONS` of **{JAVA8_OPTIONS_LIMIT} bytes** or more, or more than **64 options**, and reports no error (JDK-8288483). shirudo's documentation says the trailing options are dropped; the control run in `smoke-test.sh` saw Temurin 8 ignore the whole variable at {JAVA8_OPTIONS_LIMIT} bytes, so every agent was lost. Package and upatch names are deliberately kept short (`{UNIVERSAL_PKG}`, producing `{option(UNIVERSAL_PKG + '.jar')}`, {len(option(UNIVERSAL_PKG + '.jar'))} bytes). With every OhMyRASP package loaded the `-javaagent` options take {all_bytes} bytes of the {JAVA8_OPTIONS_LIMIT}, which leaves the rest for what other `environment.d` files set. `ohmyrasp-java8.jar` omits `Boot-Class-Path` so `appendToBootstrapClassLoaderSearch` loads the sealed `/run/shirudo-java/ohmyrasp-java8.jar` path directly. `{UNIVERSAL_PKG}.jar` omits it for the same reason, and each line appends the JAR it was started from.")
    w("")
    w("## Containers and System Services")
    w("")
    w("`systemd` user managers read `/run/environment.d/shirudo.conf` at startup and pass `JAVA_TOOL_OPTIONS` to JVMs they launch afterwards.")
    w("")
    w("- **Containers, system services, and direct logins** do not inherit user-manager `environment.d` files. Pass `-javaagent:/run/shirudo-java/<name>.jar` explicitly on the unit or container (for example via `JAVA_TOOL_OPTIONS` with the sealed JAR bind-mounted read-only).")
    w("- **Already-running JVMs** only read `JAVA_TOOL_OPTIONS` at process start and must be restarted to pick up a newly loaded or unloaded upatch.")
    w("- **A user manager that started before a load or unload** still passes the old options. Run `systemctl --user daemon-reload` as the JVM's user (or restart the manager) before restarting the JVM.")
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
    w("Validate Beefile syntax/limits, staged JAR manifests/properties, the `fixes` list and README freshness:")
    w("")
    w("```sh")
    w("python3 deploy/shirudo/gen-readmes.py --check")
    w("./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only")
    w("./deploy/shirudo/verify-shirudo-upatch.sh")
    w("```")
    w("")
    w("Run the real-JVM Docker integration suite across Temurin 8, 11, 17, 21, and 25, including a host that loads every package at once:")
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
        f"against **{vulhub.get(str(b['vulhub_jdk']), 0)}** Vulhub scripts that run the exploit on `{b['vulhub_jdk']}`"
        + (
            f" plus **{vulhub.get('java21', 0)}** on `java21`."
            if b["track"] == "java17"
            else "."
        )
    )
    w("")
    w(
        f"This package is for hosts pinned to one Java version; the universal package "
        f"[`{UNIVERSAL_PKG}`](../{UNIVERSAL_PKG}/README.md) starts the line that fits each JVM of a mixed host. "
        f"It starts its line on **{b['starts_on']}**; on any other Java it writes one `ohmyrasp-agent-skipped` JSON line to "
        "stderr and the JVM starts without this agent."
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
        f"backed by **{vulhub['total']}** end-to-end Vulhub acceptance scripts that run the exploit on a supported JVM."
    )
    w("")
    w(
        f"This package is for hosts pinned to one Java version; the universal package "
        f"[`{UNIVERSAL_PKG}`](../{UNIVERSAL_PKG}/README.md) starts the line that fits each JVM of a mixed host. "
        f"It starts its line on **{jdk25['starts_on']}**; on any other Java it writes one `ohmyrasp-agent-skipped` JSON line to "
        "stderr and the JVM starts without this agent."
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


def render_universal_readme(
    bf: dict[str, str],
    backports: list[dict[str, object]],
    jdk25: dict[str, object],
    vulhub: dict[str, int],
) -> str:
    pkg = bf["name"]
    jar = bf["source"]
    entries = fixes_check.load()
    lines: list[str] = []
    w = lines.append

    w(f"# {pkg}")
    w("")
    w("> **Generated** by `deploy/shirudo/gen-readmes.py` from `java-agent/` sources.")
    w("")
    w(
        f"OhMyRASP runtime self-protection for every Java on the host. The `{pkg}` package installs one Java upatch, "
        f"`{jar}`, a standalone, daemonless agent that holds all four OhMyRASP agent lines. Each JVM that starts "
        "with `-javaagent` on it, Java 8 to Java 25, runs the line that fits its Java version: the Java 8, 11 or 17 "
        "line, or the primary line on Java 21 and later. It hooks the JVM's own sinks (process execution, JNDI, "
        "deserialization, SQL, file writes, XXE, SSRF, expression engines) and blocks exploit-grade calls inside the "
        f"JVM, backed by **{vulhub['total']}** end-to-end Vulhub acceptance scripts that run the exploit on a supported JVM."
    )
    w("")
    w("## Install and uninstall")
    w("")
    w("```sh")
    w(f"sudo shirudo bpm install <repository>/{pkg}")
    w(f"sudo shirudo bpm uninstall {pkg}")
    w("```")
    w("")
    w(f"The upatch is also loadable on its own (`shirudo upatch load {pkg}.upatch`, `shirudo upatch unload "
      f"{pkg}.unload.upatch`). shirudo seals the JAR at `/run/shirudo-java/{jar}` and adds "
      f"`{option(jar)}` to the `JAVA_TOOL_OPTIONS` of the JVMs that systemd user managers start. "
      "A JVM that is already running has to restart to pick the change up. System services and containers do not "
      f"inherit it: pass the same `-javaagent` in their own unit or `JAVA_TOOL_OPTIONS`.")
    w("")
    w("The agent never stops a JVM from starting. A JVM that fits no line (Java 9 or 10) writes one "
      "`ohmyrasp-agent-skipped` JSON line to stderr and starts without protection. Another OhMyRASP package on the "
      "same host is harmless: one line starts per JVM and the other JAR writes `\"reason\":\"already-active\"`.")
    w("")
    render_active_section(w, start_lines(backports), "##")
    w("## Monitor and block builds")
    w("")
    w("The mode is baked into the JAR when it is built, and no control file or environment variable changes it at run "
      "time. A package built with `build.sh --mode block` (the default) blocks exploit-grade calls; one built with "
      "`build.sh --mode monitor` writes the same events with `monitor` as the action and blocks nothing. Start with "
      "a monitor build to observe a host, then install the block build. A monitor build lists no `fixes` (see below), "
      "and its `build.sh` says so when it builds.")
    w("")
    w("```sh")
    w(f"./deploy/shirudo/{pkg}/build.sh --mode monitor \"<version>\" --keys-dir \"<keys>\"")
    w("```")
    w("")
    w("## Advisories listed in `fixes`")
    w("")
    w("The block build of this package lists these advisories in the `fixes` key of its Beefile. The list means that "
      "the agent blocks the tested exploit path of that advisory inside the JVM; it does not patch the vulnerable "
      "library. A monitor build only observes, so it is packaged from a Beefile without `fixes`.")
    w("")
    w("Each advisory is backed by a Vulhub acceptance script that exploits an unprotected container and then sends the "
      "same request to a protected one. `deploy/shirudo/replay-fixes.sh` runs the scripts against the universal JAR; "
      "this table gives the date of the last replay of each entry and the JAR it ran against.")
    w("")
    w("| Advisory | Acceptance script (under `java-agent/`) | Last replayed |")
    w("|---|---|---|")
    for entry in entries:
        w(f"| {entry.id} | {', '.join(f'`{s}`' for s in entry.scripts)} | {entry.replayed} with `{entry.replayed_with}` |")
    w("")
    w("## Limits")
    w("")
    w("- A Java agent is an application-level mitigation inside the JVM, not a kernel security boundary against "
      "`root` or the JVM-launching user.")
    w(f"- OpenJDK 8 reads at most {JAVA8_OPTIONS_LIMIT} bytes of `JAVA_TOOL_OPTIONS`; the short package name keeps the "
      f"option at {len(option(jar))} bytes.")
    w("- The signed `.upatch` artifact must stay under shirudo's 16 MiB limit.")
    w("")
    w("## Documentation")
    w("")
    w(f"- [Shirudo packages: which to install, build, verify]({REPO_URL}/blob/main/deploy/shirudo/README.md)")
    w(f"- [Which JAR to attach, and what the launcher does]({REPO_URL}/blob/main/docs/agent.md#which-jar-to-attach)")
    w(f"- [Detection coverage and policies]({REPO_URL}/blob/main/docs/detection.md)")
    w(f"- [Releases]({REPO_URL}/releases)")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if any generated README is stale")
    args = parser.parse_args()

    backports = [extract_backport(t) for t in BACKPORT_TRACKS]
    jdk25 = extract_jdk25()
    primary_packages = [parse_beefile(name) for name in ("ohmyrasp-jdk21", "ohmyrasp-jdk25")]
    universal = parse_beefile(UNIVERSAL_PKG)
    vulhub = extract_vulhub_counts()
    fp = extract_fp_summary()

    # The universal Beefile's `fixes` line comes from fixes.toml, and every entry must hold (see fixes_check.py).
    beefile = fixes_check.BEEFILE
    current_beefile = beefile.read_text(encoding="utf-8")
    outputs: dict[pathlib.Path, str] = {
        beefile: fixes_check.render_beefile(current_beefile),
        SHIRUDO_DIR / "README.md": render_top_readme(backports, jdk25, primary_packages, universal, vulhub, fp),
        SHIRUDO_DIR / UNIVERSAL_PKG / "README.md": render_universal_readme(universal, backports, jdk25, vulhub),
    }
    for bf in primary_packages:
        outputs[SHIRUDO_DIR / bf["name"] / "README.md"] = render_primary_readme(jdk25, bf, vulhub)
    for b in backports:
        outputs[SHIRUDO_DIR / str(b["pkg"]) / "README.md"] = render_backport_readme(b, vulhub)

    stale: list[pathlib.Path] = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            if not args.check:
                print(f"up-to-date {path.relative_to(REPO_ROOT)}")
        elif args.check:
            stale.append(path)
        else:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path.relative_to(REPO_ROOT)}")

    # Once the Beefile is written, what is left is an entry of fixes.toml that does not hold. In --check mode a
    # Beefile that differs is already one of the stale files above.
    problems, _ = fixes_check.check(compare_beefile=False)
    for problem in problems:
        print(f"FIXES: {problem}", file=sys.stderr)
    if stale:
        for path in stale:
            print(f"STALE: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
        print("Run: python3 deploy/shirudo/gen-readmes.py", file=sys.stderr)
    if stale or problems:
        return 1
    if args.check:
        print(f"OK readmes: {len(outputs)} files up-to-date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
