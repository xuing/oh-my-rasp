#!/bin/sh
# Validate all OhMyRASP Beefiles (and staged JARs unless --beefile-only is passed)
# against shirudo's exact Beefile parser and Java upatch JAR rules. A JAR's Premain-Class must be
# its launcher entry, the baked properties must appear once, and the universal JAR must hold all four lines.

set -eu

beefile_only=0
version="0.1.0"

usage() {
	echo "usage: $0 [--beefile-only] [--version <semver>]" >&2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--beefile-only)
		beefile_only=1
		shift
		;;
	--version)
		[ $# -ge 2 ] || { usage; exit 2; }
		version=$2
		shift 2
		;;
	--version=*)
		version=${1#--version=}
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage
		exit 2
		;;
	esac
done

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

python3 - "$root" "$beefile_only" "$version" <<'PY'
import os
import re
import struct
import sys
import zlib

ROOT = sys.argv[1]
BEEFILE_ONLY = sys.argv[2] == "1"
VERSION = sys.argv[3]

LAUNCH = "io.ohmyrasp.agent.launch."

# The classes of each agent line's entry point, as paths in a JAR. The universal JAR holds all four.
LINE_ENTRIES = {
    "primary": "io/ohmyrasp/agent/OhMyRaspAgent.class",
    "java17": "io/ohmyrasp/agent/java17/OhMyRaspJava17Agent.class",
    "java11": "io/ohmyrasp/agent/java11/OhMyRaspJava11Agent.class",
    "java8": "io/ohmyrasp/agent/java8/OhMyRaspJava8Agent.class",
}

# (package, JAR may carry Boot-Class-Path, the Premain-Class its launcher entry names, the lines it must hold)
PACKAGES = [
    ("ohmyrasp", False, LAUNCH + "UniversalEntry", tuple(LINE_ENTRIES)),
    ("ohmyrasp-java8", False, LAUNCH + "Java8Entry", ()),
    ("ohmyrasp-java11", True, LAUNCH + "Java11Entry", ()),
    ("ohmyrasp-java17", True, LAUNCH + "Java17Entry", ()),
    ("ohmyrasp-jdk21", True, LAUNCH + "PrimaryEntry", ()),
    ("ohmyrasp-jdk25", True, LAUNCH + "PrimaryEntry", ()),
]

PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
BARE_KEY_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
UPATCH_NAME_CHAR_RE = re.compile(r"^[A-Za-z0-9._-]+$")
FIXES_MAX = 16
FIXES_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
UPATCH_FILE_MAX = 16 * 1024 * 1024
JAR_MANIFEST_MAX = 1 << 20
USTAR_NAME_LIMIT = 99

ZIP_END_SIG = 0x06054B50
ZIP_END_LEN = 22
ZIP_COMMENT_MAX = 65535
ZIP_ENTRY_SIG = 0x02014B50
ZIP_ENTRY_LEN = 46
ZIP_LOCAL_SIG = 0x04034B50
ZIP_LOCAL_LEN = 30
ZIP_STORED = 0
ZIP_DEFLATED = 8


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def strip_comment(line):
    basic = False
    literal = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if basic and ch == "\\":
            escaped = True
            continue
        if not literal and ch == '"':
            basic = not basic
            continue
        if not basic and ch == "'":
            literal = not literal
            continue
        if not basic and not literal and ch == "#":
            return line[:idx]
    return line


def bare_key_ok(key, allow_dots):
    if not key:
        return False
    parts = key.split(".") if allow_dots else [key]
    return all(BARE_KEY_PART_RE.match(p) for p in parts)


def parse_string(val):
    s = val.strip()
    if len(s) < 2 or s[0] not in ('"', "'"):
        raise ValueError(f"expected single-line quoted string, got {val!r}")
    quote = s[0]
    out = []
    i = 1
    while i < len(s) and s[i] != quote:
        c = s[i]
        i += 1
        if c == "\\" and quote == '"':
            if i >= len(s):
                raise ValueError("unterminated escape")
            esc = s[i]
            i += 1
            if esc == "n":
                c = "\n"
            elif esc == "r":
                c = "\r"
            elif esc == "t":
                c = "\t"
            elif esc in ("\\", '"'):
                c = esc
            else:
                raise ValueError(f"unsupported escape \\{esc}")
        out.append(c)
    if i >= len(s) or s[i] != quote:
        raise ValueError(f"unterminated string {val!r}")
    if s[i + 1 :].strip():
        raise ValueError(f"trailing characters after string: {val!r}")
    return "".join(out)


def parse_string_array(val):
    s = val.strip()
    if not s.startswith("["):
        raise ValueError(f"expected array, got {val!r}")
    i = 1
    items = []
    while True:
        while i < len(s) and s[i].isspace():
            i += 1
        if i < len(s) and s[i] == "]":
            break
        if i >= len(s) or s[i] not in ('"', "'"):
            raise ValueError(f"expected quoted string in array: {val!r}")
        quote = s[i]
        start = i
        i += 1
        while i < len(s) and s[i] != quote:
            if quote == '"' and s[i] == "\\" and i + 1 < len(s):
                i += 1
            i += 1
        if i >= len(s) or s[i] != quote:
            raise ValueError(f"unterminated string in array: {val!r}")
        i += 1
        items.append(parse_string(s[start:i]))
        while i < len(s) and s[i].isspace():
            i += 1
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        if i >= len(s) or s[i] != "]":
            raise ValueError(f"expected ',' or ']' in array: {val!r}")
    i += 1
    if s[i:].strip() or not items:
        raise ValueError(f"empty or trailing array: {val!r}")
    return items


def upatch_name_valid(name):
    if not name or name.startswith(".") or not UPATCH_NAME_CHAR_RE.match(name):
        return False
    pin_len = sum(2 if c == "." else 1 for c in name)
    return pin_len <= 255


def has_control_char(s):
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


def upatch_base(source):
    base = os.path.basename(source)
    if base.endswith(".bpf.c") or base.endswith(".bpf.o"):
        return base[:-6]
    stem, _ = os.path.splitext(base)
    return stem


def validate_beefile(pkg_name):
    beefile_path = os.path.join(ROOT, pkg_name, "Beefile")
    if not os.path.isfile(beefile_path):
        fail(f"missing Beefile: {beefile_path}")
    with open(beefile_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    if "\x00" in raw:
        fail(f"{beefile_path}: contains NUL byte")

    section = ""
    package_seen = 0
    package = {}
    upatches = []
    cur_upatch = None
    tree_owner = None
    cur_tree = None

    for lineno, orig in enumerate(raw.splitlines(), 1):
        line = strip_comment(orig).strip()
        if not line:
            continue
        if line.startswith("["):
            is_array = line.startswith("[[")
            start = 2 if is_array else 1
            close = "]]" if is_array else "]"
            end = line.find(close, start)
            if end < 0 or line[end + len(close) :] != "":
                fail(f"{beefile_path}:{lineno}: malformed table header {orig!r}")
            header = line[start:end].strip()
            if not bare_key_ok(header, True):
                fail(f"{beefile_path}:{lineno}: invalid table name {header!r}")
            section = header
            cur_upatch = None
            cur_tree = None
            if is_array and section == "upatches":
                cur_upatch = {"tree": None}
                upatches.append(cur_upatch)
                tree_owner = cur_upatch
            elif is_array and section in ("upatches.rodata", "upatches.policy"):
                fail(f"{beefile_path}:{lineno}: Java upatch Beefile must not define [[{section}]]")
            elif is_array:
                fail(f"{beefile_path}:{lineno}: unsupported array table [[{section}]]")
            elif section == "package":
                package_seen += 1
                tree_owner = None
            elif section == "upatches.tree":
                if tree_owner is None:
                    fail(f"{beefile_path}:{lineno}: [upatches.tree] before [[upatches]]")
                if tree_owner["tree"] is not None:
                    fail(f"{beefile_path}:{lineno}: duplicate [upatches.tree]")
                cur_tree = {}
                tree_owner["tree"] = cur_tree
            elif section.startswith("upatches.rodata") or section.startswith("upatches.policy"):
                fail(f"{beefile_path}:{lineno}: Java upatch Beefile must not define [{section}]")
            elif section.startswith("upatches.tree"):
                fail(f"{beefile_path}:{lineno}: unexpected tree subtable [{section}]")
            else:
                fail(f"{beefile_path}:{lineno}: unexpected table [{section}]")
            continue

        if "=" not in line:
            fail(f"{beefile_path}:{lineno}: expected key = value, got {orig!r}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not bare_key_ok(key, False):
            fail(f"{beefile_path}:{lineno}: invalid key {key!r}")
        if value in ("true", "false") or value.startswith("{"):
            fail(f"{beefile_path}:{lineno}: unsupported TOML value {value!r}")

        try:
            if section == "package":
                if key in ("name", "description", "license"):
                    package[key] = parse_string(value)
                elif key == "authors":
                    package[key] = parse_string_array(value)
                else:
                    fail(f"{beefile_path}:{lineno}: unknown [package] key {key!r}")
            elif cur_upatch is not None:
                if key in ("source", "type", "load_target", "unload_target"):
                    cur_upatch[key] = parse_string(value)
                else:
                    fail(f"{beefile_path}:{lineno}: unknown [[upatches]] key {key!r}")
            elif cur_tree is not None:
                if key == "selector":
                    fail(f"{beefile_path}:{lineno}: 'selector' key not allowed in [upatches.tree]")
                if key in ("id", "load_artifact", "unload_artifact"):
                    cur_tree[key] = parse_string(value)
                elif key == "fixes":
                    cur_tree[key] = parse_string_array(value)
                else:
                    fail(f"{beefile_path}:{lineno}: unexpected [upatches.tree] key {key!r}")
            else:
                fail(f"{beefile_path}:{lineno}: key outside supported table")
        except ValueError as exc:
            fail(f"{beefile_path}:{lineno}: {exc}")

    if package_seen != 1:
        fail(f"{beefile_path}: expected exactly one [package] table, got {package_seen}")
    name = package.get("name", "")
    if not PKG_NAME_RE.match(name):
        fail(f"{beefile_path}: invalid [package].name {name!r}")
    if name != pkg_name:
        fail(f"{beefile_path}: [package].name {name!r} does not match directory {pkg_name!r}")

    if len(upatches) != 1:
        fail(f"{beefile_path}: expected exactly one [[upatches]] table, got {len(upatches)}")
    u = upatches[0]
    if u.get("type", "").lower() != "java":
        fail(f"{beefile_path}: [[upatches]].type must be 'java', got {u.get('type')!r}")
    source = u.get("source", "")
    if not source.endswith(".jar") or source.startswith("/") or ".." in source.split("/"):
        fail(f"{beefile_path}: invalid Java upatch source {source!r}")
    base = upatch_base(source)
    if not upatch_name_valid(base):
        fail(f"{beefile_path}: invalid upatch base name {base!r}")

    tree = u.get("tree")
    if not tree or "id" not in tree:
        fail(f"{beefile_path}: [upatches.tree].id is required")
    tree_id = tree["id"]
    if has_control_char(tree_id) or not upatch_name_valid(tree_id) or tree_id != base:
        fail(f"{beefile_path}: invalid [upatches.tree].id {tree_id!r} (expected {base!r})")

    fixes = tree.get("fixes")
    if fixes is not None:
        if len(fixes) > FIXES_MAX:
            fail(f"{beefile_path}: {len(fixes)} IDs in fixes, shirudo takes at most {FIXES_MAX}")
        for advisory in fixes:
            if not FIXES_ID_RE.match(advisory):
                fail(f"{beefile_path}: fixes ID {advisory!r} is not 1 to 255 bytes of letters, digits, '.', '_', ':' and '-'")
        if len(set(fixes)) != len(fixes):
            fail(f"{beefile_path}: fixes lists an ID more than once")

    load_target = u.get("load_target", f"upatches/{base}.upatch")
    unload_target = u.get("unload_target", f"upatches/{base}.unload.upatch")
    members = [
        "Beefile",
        "README.md",
        "cert.der",
        "build-environment.json",
        load_target,
        unload_target,
    ]
    prefix = f"{name}-{VERSION}/"
    for member in members:
        full = (prefix + member).encode("utf-8")
        if len(full) >= USTAR_NAME_LIMIT:
            fail(f"{beefile_path}: tar member path {full!r} is {len(full)} bytes (must be < {USTAR_NAME_LIMIT})")

    listed = f", fixes={len(fixes)} IDs" if fixes is not None else ""
    print(f"OK beefile: {pkg_name} (name={name}, source={source}, tree.id={tree_id}{listed})")


def zip_names(data):
    """The name of every entry in the central directory, in order."""
    at = len(data) - ZIP_END_LEN
    low = at - ZIP_COMMENT_MAX if at > ZIP_COMMENT_MAX else 0
    while at >= low and struct.unpack_from("<I", data, at)[0] != ZIP_END_SIG:
        at -= 1
    if at < low:
        raise ValueError("zip end of central directory signature not found")
    entries = struct.unpack_from("<H", data, at + 10)[0]
    off = struct.unpack_from("<I", data, at + 16)[0]
    names = []
    for _ in range(entries):
        if off + ZIP_ENTRY_LEN > len(data) or struct.unpack_from("<I", data, off)[0] != ZIP_ENTRY_SIG:
            raise ValueError("corrupt central directory entry")
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, off + 28)
        names.append(data[off + ZIP_ENTRY_LEN : off + ZIP_ENTRY_LEN + name_len].decode("utf-8", errors="replace"))
        off += ZIP_ENTRY_LEN + name_len + extra_len + comment_len
    return names


def manifest_main_attribute(manifest_bytes, name):
    """The value of one main-section attribute, or None. A line that starts with a space continues the one before."""
    wanted = name.lower() + ":"
    section = []
    for raw in manifest_bytes.decode("utf-8", errors="replace").splitlines():
        if not raw:
            break
        if raw.startswith(" ") and section:
            section[-1] += raw[1:]
        else:
            section.append(raw)
    for line in section:
        if line.lower().startswith(wanted):
            return line[len(wanted) :].strip()
    return None


def zip_find_entry(data, target_name):
    if len(data) < ZIP_END_LEN:
        raise ValueError("file smaller than zip end record")
    at = len(data) - ZIP_END_LEN
    low = at - ZIP_COMMENT_MAX if at > ZIP_COMMENT_MAX else 0
    while struct.unpack_from("<I", data, at)[0] != ZIP_END_SIG:
        if at == low:
            raise ValueError("zip end of central directory signature not found")
        at -= 1
    entries = struct.unpack_from("<H", data, at + 10)[0]
    dir_off = struct.unpack_from("<I", data, at + 16)[0]
    if entries == 0xFFFF or dir_off == 0xFFFFFFFF:
        raise ValueError("zip64 archive is not supported by shirudo")
    if dir_off > at:
        raise ValueError("central directory offset past end record")

    off = dir_off
    target_lower = target_name.lower()
    for _ in range(entries):
        if off + ZIP_ENTRY_LEN > len(data) or struct.unpack_from("<I", data, off)[0] != ZIP_ENTRY_SIG:
            raise ValueError("corrupt central directory entry")
        method = struct.unpack_from("<H", data, off + 10)[0]
        packed_len = struct.unpack_from("<I", data, off + 20)[0]
        unpacked_len = struct.unpack_from("<I", data, off + 24)[0]
        name_len = struct.unpack_from("<H", data, off + 28)[0]
        extra_len = struct.unpack_from("<H", data, off + 30)[0]
        comment_len = struct.unpack_from("<H", data, off + 32)[0]
        local_off = struct.unpack_from("<I", data, off + 42)[0]
        if off + ZIP_ENTRY_LEN + name_len + extra_len + comment_len > len(data):
            raise ValueError("central directory entry out of bounds")
        name_bytes = data[off + ZIP_ENTRY_LEN : off + ZIP_ENTRY_LEN + name_len]
        if name_bytes.decode("utf-8", errors="replace").lower() == target_lower:
            return method, packed_len, unpacked_len, local_off
        off += ZIP_ENTRY_LEN + name_len + extra_len + comment_len
    return None


def zip_read_entry(data, entry):
    method, packed_len, unpacked_len, local_off = entry
    if unpacked_len > JAR_MANIFEST_MAX:
        raise ValueError(f"entry too large ({unpacked_len} > {JAR_MANIFEST_MAX})")
    if method not in (ZIP_STORED, ZIP_DEFLATED):
        raise ValueError(f"unsupported zip compression method {method}")
    if method == ZIP_STORED and packed_len != unpacked_len:
        raise ValueError("stored zip entry packed_len != unpacked_len")
    if local_off + ZIP_LOCAL_LEN > len(data) or struct.unpack_from("<I", data, local_off)[0] != ZIP_LOCAL_SIG:
        raise ValueError("corrupt zip local file header")
    l_name_len = struct.unpack_from("<H", data, local_off + 26)[0]
    l_extra_len = struct.unpack_from("<H", data, local_off + 28)[0]
    start = local_off + ZIP_LOCAL_LEN + l_name_len + l_extra_len
    if start + packed_len > len(data):
        raise ValueError("zip entry payload out of bounds")
    payload = data[start : start + packed_len]
    if method == ZIP_STORED:
        return payload
    out = zlib.decompress(payload, -zlib.MAX_WBITS)
    if len(out) != unpacked_len:
        raise ValueError("deflated entry length mismatch")
    return out


def manifest_has_premain(manifest_bytes):
    at = 0
    length = len(manifest_bytes)
    attr = b"premain-class:"
    while at < length and manifest_bytes[at : at + 1] not in (b"\n", b"\r"):
        end = at
        while end < length and manifest_bytes[end : end + 1] not in (b"\n", b"\r"):
            end += 1
        line = manifest_bytes[at:end]
        if len(line) > len(attr) and line[: len(attr)].lower() == attr:
            rest = line[len(attr) :]
            if any(b != ord(" ") and not chr(b).isspace() for b in rest):
                return True
            return False
        at = end
        if at < length and manifest_bytes[at : at + 1] == b"\r":
            at += 1
        if at < length and manifest_bytes[at : at + 1] == b"\n":
            at += 1
    return False


def validate_jar(pkg_name, allow_boot_classpath, premain_class, required_lines):
    jar_path = os.path.join(ROOT, pkg_name, f"{pkg_name}.jar")
    if not os.path.isfile(jar_path):
        fail(f"missing staged JAR: {jar_path}")
    size = os.path.getsize(jar_path)
    if size <= 0 or size >= UPATCH_FILE_MAX:
        fail(f"{jar_path}: size {size} bytes must be in (0, {UPATCH_FILE_MAX})")

    with open(jar_path, "rb") as fh:
        data = fh.read()

    try:
        manifest_entry = zip_find_entry(data, "META-INF/MANIFEST.MF")
        if manifest_entry is None:
            fail(f"{jar_path}: missing META-INF/MANIFEST.MF in ZIP central directory")
        manifest_bytes = zip_read_entry(data, manifest_entry)
    except ValueError as exc:
        fail(f"{jar_path}: {exc}")

    if not manifest_has_premain(manifest_bytes):
        fail(f"{jar_path}: META-INF/MANIFEST.MF main section missing non-empty Premain-Class:")

    premain = manifest_main_attribute(manifest_bytes, "Premain-Class")
    if premain != premain_class:
        fail(f"{jar_path}: Premain-Class is {premain!r}, expected the launcher entry {premain_class!r}")

    if not allow_boot_classpath:
        for line in manifest_bytes.splitlines():
            if line.lower().startswith(b"boot-class-path:"):
                fail(f"{jar_path}: Java 8 JAR must not contain Boot-Class-Path: in MANIFEST.MF")

    try:
        names = zip_names(data)
    except ValueError as exc:
        fail(f"{jar_path}: {exc}")
    baked = names.count("META-INF/ohmyrasp-shirudo.properties")
    if baked != 1:
        fail(f"{jar_path}: META-INF/ohmyrasp-shirudo.properties appears {baked} times, expected exactly once")
    for line in required_lines:
        if LINE_ENTRIES[line] not in names:
            fail(f"{jar_path}: the {line} line is missing: no {LINE_ENTRIES[line]}")

    try:
        props_entry = zip_find_entry(data, "META-INF/ohmyrasp-shirudo.properties")
        if props_entry is None:
            fail(f"{jar_path}: missing META-INF/ohmyrasp-shirudo.properties")
        props_bytes = zip_read_entry(data, props_entry)
    except ValueError as exc:
        fail(f"{jar_path}: {exc}")

    props = {}
    for raw_line in props_bytes.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
        elif ":" in line:
            k, v = line.split(":", 1)
        else:
            continue
        props[k.strip()] = v.strip()

    expected = {
        "standalone": "true",
        "lock_config": "true",
        "control": "none",
        "log": "stderr",
        "latency_sample": "0",
    }
    for k, want in expected.items():
        got = props.get(k)
        if got != want:
            fail(f"{jar_path}: META-INF/ohmyrasp-shirudo.properties {k}={got!r}, expected {want!r}")

    held = f", lines: {' '.join(required_lines)}" if required_lines else ""
    print(f"OK jar: {pkg_name}.jar ({size} bytes, Premain-Class {premain}{held})")


for pkg_name, allow_boot_cp, premain_class, lines in PACKAGES:
    validate_beefile(pkg_name)
    if not BEEFILE_ONLY:
        validate_jar(pkg_name, allow_boot_cp, premain_class, lines)

print("ALL CHECKS PASSED")
PY

if [ -d "$root/../../java-agent" ] && [ -f "$root/gen-readmes.py" ]; then
	python3 "$root/gen-readmes.py" --check
else
	echo "SKIP: java-agent/ not present; skipping gen-readmes.py --check"
fi
