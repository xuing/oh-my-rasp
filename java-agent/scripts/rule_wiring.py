"""Which primary rule ids a hook module can reach, worked out from the agent-jdk25 sources.

A rule id is reached when a method that names it as a string (to build a Detection) can run after some
hook module injects a call to an OhMyRaspHooks entry method. The map is read, not run:

* the roots are the OhMyRaspHooks methods a module or shared visitor names (the injected call is
  `invokeHook("name", ...)` or `visitMethodInsn(INVOKESTATIC, hooks, "name", ...)`, so the name is a
  string literal under asm/ or shared/, alone or as the signature `void name(Type)` of a Method), and every method of the agent classes outside hook/OhMyRaspHooks
  and detect/ (the policy, control and runtime classes the hooks call back into, and the classes the
  agent installs itself, such as DeserializationGuard);
* the edges are the calls in a method body: `Type.name(`, `new Type(`, `Type::name`, and `name(` in the
  same class. A call on a value, `x.name(`, is taken to reach every agent method called `name`, so the
  map can only err towards reachable: a rule it calls unreachable is unreachable.

What it cannot see: a rule that its method reaches only on a branch no input takes (the one such case,
expression_runtime, has its own check: engine_names_without_an_id), and a call the agent makes by reflection
under a name it builds at run time. A name written as a literal is read, so the reflective calls of the
EL, JEXL and OSGi servlet paths count.

Used by test_rule_cases.py (WiringTest); the catalogue marks the ids it finds as not wired ("not_wired" in
rules/general.json and product.json).
"""
from __future__ import annotations

import functools
import re
from pathlib import Path

import rule_catalogue

ROOT = Path(__file__).resolve().parent.parent  # java-agent/
AGENT = ROOT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
SHARED = ROOT / "shared" / "src" / "main" / "java"
ASM = AGENT / "asm"
HOOKS_CLASS = "OhMyRaspHooks"

_KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "try", "return", "new", "else", "do",
             "throw", "assert", "super", "this"}
_SCOPE = re.compile(r"\b(class|interface|enum|record)\s+(\w+)")
_METHOD = re.compile(r"(\w+)\s*\((?:[^()]|\([^()]*\))*\)\s*(?:throws\s+[\w.,\s]+)?$")


def strip(source: str) -> tuple[str, list[str]]:
    """The source without comments, each string literal replaced by `"§n§"` (n indexes the returned list)
    and each char literal by `' '`, so a brace or parenthesis inside either never counts."""
    out: list[str] = []
    literals: list[str] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if source.startswith("//", i):
            i = source.find("\n", i)
            i = n if i < 0 else i
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            out.append(" ")
            i = n if end < 0 else end + 2
        elif source.startswith('"""', i):
            end = source.find('"""', i + 3)
            while end > 0 and source[end - 1] == "\\":
                end = source.find('"""', end + 1)
            end = n if end < 0 else end
            literals.append(source[i + 3:end])
            out.append(f'"§{len(literals) - 1}§"')
            i = end + 3
        elif c == '"':
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            literals.append(source[i + 1:j])
            out.append(f'"§{len(literals) - 1}§"')
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and source[j] != "'":
                j += 2 if source[j] == "\\" else 1
            out.append("' '")
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out), literals


class Method:
    def __init__(self, owner: str, name: str, body: str, table: list[str]):
        self.owner, self.name, self.body, self.table = owner, name, body, table

    @property
    def key(self) -> tuple[str, str]:
        return self.owner, self.name


def methods(path: Path) -> list[Method]:
    """The methods of a source file, each with the text of its body (a nested or anonymous class is part of the
    method that holds it). Class-level text outside any method (field initialisers) is the pseudo method `<init>`."""
    text, literals = strip(path.read_text(encoding="utf-8"))
    found: list[Method] = []
    # stack entries: ("class", name, field_text_parts) or ("method", Method, start_index, depth_at_open)
    scopes: list[list] = []
    header_start = 0
    depth = 0
    method_depth = 0  # braces opened inside the current method body
    current: list | None = None

    def class_scope() -> list | None:
        return next((s for s in reversed(scopes) if s[0] == "class"), None)

    for i, ch in enumerate(text):
        if current is not None:
            if ch == "{":
                method_depth += 1
            elif ch == "}":
                method_depth -= 1
                if method_depth == 0:
                    body = text[current[2]:i]
                    found.append(Method(current[1], current[3], body, literals))
                    current = None
                    header_start = i + 1
            continue
        if ch == "{":
            header = text[header_start:i]
            scope = list(_SCOPE.finditer(header))
            cls = class_scope()
            if scope and not re.search(r"\bnew\b", header):
                if cls is not None:
                    cls[2].append(text[header_start:header_start])
                scopes.append(["class", scope[-1].group(2), []])
            elif cls is not None and (m := _METHOD.search(header.strip())) and m.group(1) not in _KEYWORDS:
                current = ["method", cls[1], i + 1, m.group(1)]
                method_depth = 1
            else:  # an initialiser block, an array initialiser, an enum constant body
                scopes.append(["block", "", []])
            header_start = i + 1
        elif ch == "}":
            if scopes:
                scope = scopes.pop()
                if scope[0] == "class":
                    body = "".join(scope[2])
                    found.append(Method(scope[1], "<init>", body, literals))
            header_start = i + 1
        elif ch == ";":
            cls = class_scope()
            if cls is not None and scopes[-1][0] == "class":
                cls[2].append(text[header_start:i + 1])
            header_start = i + 1
    return found


@functools.cache
def _agent_methods() -> tuple[Method, ...]:
    return tuple(m for p in sorted(AGENT.rglob("*.java")) for m in methods(p))


def _package_of(path: Path) -> str:
    return path.relative_to(AGENT).parts[0] if len(path.relative_to(AGENT).parts) > 1 else ""


@functools.cache
def _owner_package() -> dict[str, str]:
    return {p.stem: _package_of(p) for p in AGENT.rglob("*.java")}


def entry_methods() -> set[str]:
    return {m.name for m in _agent_methods() if m.owner == HOOKS_CLASS}


def named_in_emitters() -> set[str]:
    """OhMyRaspHooks entry names that appear as a string literal under asm/ or shared/: the injected calls."""
    names = entry_methods()
    found: set[str] = set()
    for base in (ASM, SHARED):
        for path in base.rglob("*.java"):
            _, literals = strip(path.read_text(encoding="utf-8"))
            for literal in literals:
                found |= names & set(re.findall(r"\b(\w+)\(", literal) + [literal])
    return found


_CALL = re.compile(r"(?:\b([A-Za-z_]\w*)\s*(\.|::)\s*)?\b([A-Za-z_]\w*)\s*\(|\b([A-Z]\w*)\s*::\s*(\w+)|\bnew\s+([A-Z]\w*)")


@functools.cache
def _graph() -> tuple[dict[tuple[str, str], Method], dict[str, list[tuple[str, str]]]]:
    by_key: dict[tuple[str, str], list[Method]] = {}
    for m in _agent_methods():
        by_key.setdefault(m.key, []).append(m)
    by_name: dict[str, list[tuple[str, str]]] = {}
    for key in by_key:
        by_name.setdefault(key[1], []).append(key)
    return by_key, by_name


def _edges(method: Method) -> set[tuple[str, str]]:
    by_key, by_name = _graph()
    classes = {owner for owner, _ in by_key}
    out: set[tuple[str, str]] = set()
    body = method.body
    for m in re.finditer(r"\bnew\s+([A-Z]\w*)", body):
        out |= {k for k in by_key if k[0] == m.group(1)}
    for m in re.finditer(r"\b([A-Z]\w*)\s*::\s*(\w+)", body):
        out |= {(m.group(1), m.group(2))} & by_key.keys()
    for m in re.finditer(r"(?:(\b[A-Za-z_]\w*|\))\s*\.\s*)?\b([A-Za-z_]\w*)\s*\(", body):
        qualifier, name = m.group(1), m.group(2)
        if name in _KEYWORDS:
            continue
        if qualifier in classes:
            out |= {(qualifier, name)} & by_key.keys()
        elif qualifier is None or qualifier == "this":
            own = {(method.owner, name)} & by_key.keys()
            out |= own or set(by_name.get(name, ()))  # an inherited, outer-class or statically imported method
        else:
            out |= set(by_name.get(name, ()))
    for m in re.finditer(r"(?:\bthis|\b[a-z]\w*)\s*::\s*(\w+)", body):
        out |= set(by_name.get(m.group(1), ()))
    return out


@functools.cache
def reachable_methods() -> frozenset[tuple[str, str]]:
    """Methods that can run once some module has injected a call: see the module docstring for the roots."""
    by_key, _ = _graph()
    packages = _owner_package()
    roots = {(HOOKS_CLASS, name) for name in named_in_emitters()}
    roots |= {key for key in by_key if key[0] != HOOKS_CLASS and packages.get(key[0]) not in ("detect", "asm")}
    seen: set[tuple[str, str]] = set()
    todo = [k for k in roots if k in by_key]
    while todo:
        key = todo.pop()
        if key in seen:
            continue
        seen.add(key)
        for method in by_key[key]:
            for edge in _edges(method):
                if edge not in seen:
                    todo.append(edge)
        # a class's field initialisers run when one of its methods does
        if (key[0], "<init>") in by_key and (key[0], "<init>") not in seen:
            todo.append((key[0], "<init>"))
    return frozenset(seen)


def emitted_ids(method: Method) -> set[str]:
    """Catalogue ids the method writes as a literal, except where it only compares or selects by one:
    `"id".equals(x)`, `x.equals("id")` and `policy.selectsAlgorithm("id")` build no Detection."""
    ids = rule_catalogue.primary_ids()
    out: set[str] = set()
    for m in re.finditer(r"§(\d+)§", method.body):
        literal = method.table[int(m.group(1))]
        if literal not in ids:
            continue
        before = method.body[:m.start()].rstrip().removesuffix('"').rstrip()
        after = method.body[m.end():].lstrip().removeprefix('"').lstrip()
        if re.search(r"\.(equals|equalsIgnoreCase|selectsAlgorithm)\($", before) or re.match(r"\.\s*equals", after):
            continue
        out.add(literal)
    return out


@functools.cache
def emitters() -> dict[str, set[tuple[str, str]]]:
    """Primary rule id -> the agent methods that build a Detection with it."""
    found: dict[str, set[tuple[str, str]]] = {}
    for method in _agent_methods():
        if _owner_package().get(method.owner) in ("detect", "hook"):
            for rule in emitted_ids(method):
                found.setdefault(rule, set()).add(method.key)
    return found


def unreachable_ids() -> dict[str, set[tuple[str, str]]]:
    """Primary rule id -> its emitting methods, for each id no emitter of which is reachable. An id with no
    emitter at all (built from a computed string) is not in the result: the check cannot say anything about it."""
    reach = reachable_methods()
    return {rule: keys for rule, keys in sorted(emitters().items()) if not keys & reach}


def engine_names_without_an_id() -> set[str]:
    """Engine names ExpressionHookModule passes to beforeExpressionEvaluation that CodeExecutionDetector.detectExpression
    would report as expression_runtime, its default: the names that have no `case` of their own (and are not "ognl",
    which detectExpression hands to detectOgnl first).

    The one rule id the call graph cannot judge: detectExpression is reachable, only its default branch is not.
    """
    module = (ASM / "ExpressionHookModule.java").read_text(encoding="utf-8")
    pushed = set(re.findall(r'\bpush\("(\w+)"\)', module))
    pushed |= set(re.findall(r'return "(\w+)";', module[module.index("engineForScriptClass"):]))
    detect = next(m for m in _agent_methods() if m.key == ("CodeExecutionDetector", "detectExpression"))
    cases: set[str] = {"ognl"}
    for labels in re.findall(r"\bcase\s+((?:\"§\d+§\"\s*,?\s*)+)->", detect.body):
        cases |= {detect.table[int(i)] for i in re.findall(r"§(\d+)§", labels)}
    return pushed - cases


# Ids that a reachable method emits only on one branch: id -> True when some hook module can take the branch.
BRANCH_CHECKS = {"expression_runtime": lambda: bool(engine_names_without_an_id())}


def reachable_ids() -> set[str]:
    """Primary ids some hook module can make an agent report, as far as the sources show."""
    reach = reachable_methods()
    ids = {rule for rule, keys in emitters().items() if keys & reach}
    for rule, taken in BRANCH_CHECKS.items():
        ids.discard(rule)
        if taken():
            ids.add(rule)
    return ids


def unreachable_primary_ids() -> set[str]:
    """Primary ids no hook module can make an agent report: every catalogue id that is not reachable (an id
    nothing emits, such as one the catalogue describes but no detector writes, counts)."""
    return rule_catalogue.primary_ids() - reachable_ids()


def ids_reported_by(class_name: str, method: str) -> set[str]:
    """Primary ids the methods called `method` in `class_name` can report, through everything they call."""
    by_key, _ = _graph()
    reverse: dict[tuple[str, str], set[str]] = {}
    for rule, keys in emitters().items():
        for key in keys:
            reverse.setdefault(key, set()).add(rule)
    seen: set[tuple[str, str]] = set()
    todo = [(class_name, method)]
    found: set[str] = set()
    while todo:
        key = todo.pop()
        if key in seen or key not in by_key:
            continue
        seen.add(key)
        found |= reverse.get(key, set())
        for m in by_key[key]:
            todo.extend(edge for edge in _edges(m) if edge not in seen)
    return found


def serves_only_not_wired(class_name: str, method: str) -> bool:
    """True for a detector entry point whose every rule id the catalogue marks not wired: no hook needs it."""
    ids = ids_reported_by(class_name, method)
    return bool(ids) and ids <= rule_catalogue.not_wired().keys()
