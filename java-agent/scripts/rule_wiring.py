"""Which primary rule ids a hook module can reach, worked out from the agent-jdk25 sources.

A rule id is reached when a method that names it as a string (to build a Detection) can run after some
hook module injects a call to an OhMyRaspHooks entry method. The map is read, not run:

* the roots are the OhMyRaspHooks methods a module or shared visitor names (the injected call is
  `invokeHook("name", ...)` or `visitMethodInsn(INVOKESTATIC, hooks, "name", ...)`, so the name is a
  string literal under asm/ or shared/, alone or as the signature `void name(Type)` of a Method), and every
  method of the agent classes outside OhMyRaspHooks, detect/ and asm/ (the policy, control and runtime
  classes the hooks call back into, and the classes the agent installs itself, such as DeserializationGuard);
* the edges are the calls in a method body, matched by name and by number of arguments: `Type.name(`,
  `new Type(`, `Type::name`, `name(` in the same class or a superclass, and `x.name(` where the declared
  type of `x` is a parameter, local variable or field of the same class (or `var x = new Type(`): it reaches
  that type and its subtypes, and nothing at all when the type is not an agent class (a List, a String).

What it cannot see, and what is still over-approximated: a call on a value whose type it cannot read (a
chain `a.b().name(`, a lambda parameter, a field of another class) reaches every agent method of that name
and arity; two overloads with the same number of parameters are one method; the same-named method of an
outer class is taken for an unqualified call it cannot find in the class itself. All of these err towards
reachable, so a rule it calls unreachable is unreachable. It cannot see a branch inside a reachable method
that no input takes (expression_runtime has its own check, engine_names_without_an_id), a call the agent
makes by reflection under a name it builds at run time (a name written as a literal is read, so the EL,
JEXL and OSGi servlet paths count), or a value only a hook supplies (the request body: see BODY_ONLY, which
counts a body as supplied when a reachable method hands one to a RequestContext).

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


_METHOD = re.compile(r"(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)\s*(?:throws\s+[\w.,\s]+)?$")
_CLASS_HEADER = re.compile(r"\b(?:class|interface|enum|record)\s+(\w+)(?:<[^{]*?>)?(?:\([^)]*\))?\s*((?:extends|implements)\b[^{]*)\{")


def count_arguments(text: str) -> int:
    """The number of top-level, comma-separated items in `text` (a parameter or argument list, without its parentheses)."""
    if not text.strip():
        return 0
    depth = angle = count = 0
    for i, c in enumerate(text):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "<" and i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_") and i + 1 < len(text) \
                and (text[i + 1].isupper() or text[i + 1] == "?"):
            angle += 1
        elif c == ">" and angle and text[i - 1] != "-":
            angle -= 1
        elif c == "," and depth == 0 and angle == 0:
            count += 1
    return count + 1


class Method:
    """One method (or constructor) of a source file: `arity` is the number of declared parameters, and a
    varargs method (`varargs`) takes that many or more less one."""

    def __init__(self, owner: str, name: str, params: str, body: str, table: list[str], package: str):
        self.owner, self.name, self.params, self.body, self.table, self.package = owner, name, params, body, table, package
        self.arity = count_arguments(params)
        self.varargs = "..." in params

    @property
    def key(self) -> tuple[str, str, int]:
        return self.owner, self.name, self.arity

    def takes(self, arguments: int) -> bool:
        return arguments == self.arity or (self.varargs and arguments >= self.arity - 1)


def methods(path: Path, package: str = "") -> list[Method]:
    """The methods of a source file, each with the text of its body (a nested or anonymous class is part of the
    method that holds it). Class-level text outside any method (field initialisers) is the pseudo method `<init>`."""
    text, literals = strip(path.read_text(encoding="utf-8"))
    found: list[Method] = []
    scopes: list[list] = []  # ["class", name, field_text_parts] or ["block", "", []]
    header_start = 0
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
                    found.append(Method(current[1], current[3], current[4], text[current[2]:i], literals, package))
                    current = None
                    header_start = i + 1
            continue
        if ch == "{":
            header = text[header_start:i]
            scope = list(_SCOPE.finditer(header))
            cls = class_scope()
            if scope and not re.search(r"\bnew\b", header):
                scopes.append(["class", scope[-1].group(2), []])
            elif cls is not None and (m := _METHOD.search(header.strip())) and m.group(1) not in _KEYWORDS:
                current = ["method", cls[1], i + 1, m.group(1), m.group(2)]
                method_depth = 1
            else:  # an initialiser block, an array initialiser, an enum constant body
                scopes.append(["block", "", []])
            header_start = i + 1
        elif ch == "}":
            if scopes:
                scope = scopes.pop()
                if scope[0] == "class":
                    found.append(Method(scope[1], "<init>", "", "".join(scope[2]), literals, package))
            header_start = i + 1
        elif ch == ";":
            cls = class_scope()
            if cls is not None and scopes[-1][0] == "class":
                cls[2].append(text[header_start:i + 1])
            header_start = i + 1
    return found


def _package_of(path: Path) -> str:
    parts = path.relative_to(AGENT).parts
    return parts[0] if len(parts) > 1 else ""


@functools.cache
def _agent_methods() -> tuple[Method, ...]:
    return tuple(m for p in sorted(AGENT.rglob("*.java")) for m in methods(p, _package_of(p)))


@functools.cache
def _supers() -> dict[str, set[str]]:
    """Class or interface name -> the names its header extends or implements."""
    found: dict[str, set[str]] = {}
    for path in AGENT.rglob("*.java"):
        text, _ = strip(path.read_text(encoding="utf-8"))
        for name, clause in _CLASS_HEADER.findall(text):
            clause = re.sub(r"<[^<>]*(?:<[^<>]*>[^<>]*)*>", "", clause)
            found.setdefault(name, set()).update(re.findall(r"[A-Z]\w*", clause))
    return found


@functools.cache
def _ancestors(name: str) -> frozenset[str]:
    seen: set[str] = set()
    todo = [name]
    while todo:
        for parent in _supers().get(todo.pop(), ()):
            if parent not in seen:
                seen.add(parent)
                todo.append(parent)
    return frozenset(seen)


@functools.cache
def _subtypes(name: str) -> frozenset[str]:
    return frozenset({name} | {c for c in _supers() if name in _ancestors(c)})


def entry_methods() -> set[str]:
    return {m.name for m in _agent_methods() if m.owner == HOOKS_CLASS}


@functools.cache
def named_in_emitters() -> frozenset[str]:
    """OhMyRaspHooks entry names that appear as a string literal under asm/ or shared/: the injected calls."""
    names = entry_methods()
    found: set[str] = set()
    for base in (ASM, SHARED):
        for path in base.rglob("*.java"):
            _, literals = strip(path.read_text(encoding="utf-8"))
            for literal in literals:
                found |= names & set(re.findall(r"\b(\w+)\(", literal) + [literal])
    return frozenset(found)


@functools.cache
def _graph() -> tuple[dict[tuple[str, str, int], list[Method]], dict[tuple[str, str], list[Method]], dict[str, list[Method]]]:
    """Methods by key, by (owner, name) and by name."""
    by_key: dict[tuple[str, str, int], list[Method]] = {}
    by_owner: dict[tuple[str, str], list[Method]] = {}
    by_name: dict[str, list[Method]] = {}
    for m in _agent_methods():
        by_key.setdefault(m.key, []).append(m)
        by_owner.setdefault((m.owner, m.name), []).append(m)
        by_name.setdefault(m.name, []).append(m)
    return by_key, by_owner, by_name


@functools.cache
def _classes() -> frozenset[str]:
    return frozenset(m.owner for m in _agent_methods())


@functools.cache
def _fields(owner: str) -> str:
    """The field declarations of a class: its `<init>` text, and that of the classes in the same file (an outer or nested class)."""
    return "\n".join(m.body for m in _agent_methods() if m.name == "<init>" and m.owner == owner)


_PRIMITIVES = {"int", "long", "boolean", "double", "float", "char", "byte", "short", "void"}
_NOT_TYPES = _KEYWORDS | {"instanceof", "case", "default", "throws", "extends", "implements", "static", "final", "var"}


@functools.cache
def _declaration(name: str) -> re.Pattern:
    return re.compile(r"(?<![\w.])([A-Za-z_][\w.]*)\s*(?:<[^;(){}]*?>)?\s*(?:\[\]\s*)*\s+(?:final\s+)?"
                      + re.escape(name) + r"\b(?!\s*\()")


@functools.cache
def declared_type(method: Method, name: str) -> str | None:
    """The simple type name `name` is declared with as a parameter, local variable or field of the method's class:
    None when it is not declared there. `var x = new T(` is T; a `var` with another initialiser is None."""
    for text in (method.params, method.body, _fields(method.owner)):
        for m in _declaration(name).finditer(text):
            kind = m.group(1).rsplit(".", 1)[-1]
            if kind in _NOT_TYPES and kind != "var":
                continue
            if kind == "var":
                init = re.match(r"\s*=\s*(?:\([\w.<>]+\)\s*)?new\s+([A-Z]\w*)", text[m.end():])
                if init:
                    return init.group(1)
                continue
            return kind
    return None


def _arguments(body: str, open_at: int) -> int:
    """The number of arguments of the call whose `(` is at `open_at`."""
    depth = 0
    for i in range(open_at, len(body)):
        if body[i] in "([{":
            depth += 1
        elif body[i] in ")]}":
            depth -= 1
            if depth == 0:
                return count_arguments(body[open_at + 1:i])
    return -1


_CALL = re.compile(r"(?:(\b[A-Za-z_]\w*|\))\s*\.\s*)?\b([A-Za-z_]\w*)\s*\(")
_NEW = re.compile(r"\bnew\s+([A-Z]\w*)\s*(?:<[^()]*?>)?\s*\(")


def _resolve(owners: set[str], name: str, arguments: int) -> set[tuple[str, str, int]]:
    _, by_owner, _ = _graph()
    return {m.key for owner in owners for m in by_owner.get((owner, name), ()) if arguments < 0 or m.takes(arguments)}


def _by_name(name: str, arguments: int) -> set[tuple[str, str, int]]:
    _, _, by_name = _graph()
    return {m.key for m in by_name.get(name, ()) if arguments < 0 or m.takes(arguments)}


@functools.cache
def _edges(method: Method) -> frozenset[tuple[str, str, int]]:
    by_key, by_owner, _ = _graph()
    classes = _classes()
    out: set[tuple[str, str, int]] = set()
    body = method.body
    for m in _NEW.finditer(body):
        if m.group(1) in classes:
            out |= _resolve({m.group(1)}, m.group(1), _arguments(body, m.end() - 1))
            out |= {k for k in by_key if k[0] == m.group(1) and k[1] == "<init>"}
    for m in re.finditer(r"\b([A-Z]\w*)\s*::\s*(\w+)", body):
        if m.group(1) in classes:
            out |= _resolve({m.group(1)}, m.group(2), -1)
    for m in re.finditer(r"\b(this|[a-z_]\w*)\s*::\s*(\w+)", body):
        own = {method.owner} | _ancestors(method.owner)
        out |= (_resolve(own, m.group(2), -1) if m.group(1) == "this" else _by_name(m.group(2), -1))
    for m in _CALL.finditer(body):
        qualifier, name = m.group(1), m.group(2)
        if name in _KEYWORDS or (qualifier is None and body[max(0, m.start() - 4):m.start()].endswith("new ")):
            continue
        arguments = _arguments(body, m.end() - 1)
        if qualifier is None or qualifier == "this" or qualifier == "super":
            own = {method.owner} | _ancestors(method.owner)
            found = _resolve(own, name, arguments)
            out |= found or _by_name(name, arguments)  # an outer-class or statically imported method
            continue
        kind = declared_type(method, qualifier) if qualifier != ")" else None
        if kind is None and qualifier in classes and qualifier != ")":
            out |= _resolve({qualifier}, name, arguments)  # a static call
        elif kind is not None:
            if kind in classes:
                out |= _resolve(set(_subtypes(kind)), name, arguments)
            # a type outside the agent (String, List, a JDK class): its methods are not ours
        elif qualifier[0].isupper() and not qualifier.isupper():
            pass  # Optional.of(, Map.of(, Objects.requireNonNull(: a class outside the agent
        else:
            out |= _by_name(name, arguments)  # a value whose type is not declared here
    return frozenset(out)


@functools.cache
def reachable_methods() -> frozenset[tuple[str, str, int]]:
    """Method keys (class, name, number of parameters) that can run once some module has injected a call."""
    by_key, _, _ = _graph()
    roots = {m.key for m in _agent_methods() if m.owner == HOOKS_CLASS and m.name in named_in_emitters()}
    roots |= {m.key for m in _agent_methods() if m.owner != HOOKS_CLASS and m.package not in ("detect", "asm")}
    seen: set[tuple[str, str, int]] = set()
    todo = [k for k in roots if k in by_key]
    while todo:
        key = todo.pop()
        if key in seen:
            continue
        seen.add(key)
        for method in by_key[key]:
            todo.extend(edge for edge in _edges(method) if edge not in seen)
        # a class's field initialisers run when one of its methods does
        init = (key[0], "<init>", 0)
        if init in by_key and init not in seen:
            todo.append(init)
    return frozenset(seen)


def is_reachable(owner: str, name: str) -> bool:
    return any(k[0] == owner and k[1] == name for k in reachable_methods())


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
def emitters() -> dict[str, set[tuple[str, str, int]]]:
    """Primary rule id -> the agent methods that build a Detection with it."""
    found: dict[str, set[tuple[str, str, int]]] = {}
    for method in _agent_methods():
        if method.package in ("detect", "hook"):
            for rule in emitted_ids(method):
                found.setdefault(rule, set()).add(method.key)
    return found


def unreachable_ids() -> dict[str, set[tuple[str, str, int]]]:
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
    detect = next(m for m in _agent_methods() if m.owner == "CodeExecutionDetector" and m.name == "detectExpression")
    cases: set[str] = {"ognl"}
    for labels in re.findall(r"\bcase\s+((?:\"§\d+§\"\s*,?\s*)+)->", detect.body):
        cases |= {detect.table[int(i)] for i in re.findall(r"§(\d+)§", labels)}
    return pushed - cases


_BODY_ARGUMENT = re.compile(r"new RequestContext\([^;]*,\s*body\s*\)|\.observeBody\(")


def request_body_sources() -> set[tuple[str, str, int]]:
    """Reachable methods outside detect/ that give a RequestContext a request body: one built from a `body` they
    were given, or one that hands a context the body the application has read (`observeBody`, which the
    request-body hooks reach: RequestBodyVisitor injects the exitBody* calls into servlet input streams and
    Tomcat's reader). The others copy the body a context already has, and the servlet entry builds its context
    without one."""
    reach = reachable_methods()
    return {m.key for m in _agent_methods()
            if m.key in reach and m.package != "detect" and _BODY_ARGUMENT.search(m.body)}


# Rules whose decision reads only the request body (`request.body()` blank means no finding): the detectors are
# reached, but with an empty body unless some reachable method supplies one. The request-body hooks supply it
# (measured with the rule-cases probe: a body the handler reads through getInputStream() or getReader() fires them).
BODY_ONLY = {
    "request_json_patch_expression": "RequestExpressionDetector.jsonPatchExpression",
    "request_message_selector_expression": "RequestConfigurationDetector.messageSelectorExpression",
    "request_xml_polymorphic_gadget": "RequestPayloadDetector (xml polymorphic gadget, returns on a blank body)",
    "request_sql_identifier_injection": "SqlRequestIndicators.sqlRequestMetadata, called when the body is not blank",
    "request_sql_sort_injection": "SqlRequestIndicators.sqlRequestMetadata, called when the body is not blank",
}

# Ids that a reachable method emits only on one branch, or only for an input a hook may not supply:
# id -> True when some hook module can take the branch.
BRANCH_CHECKS = {"expression_runtime": lambda: bool(engine_names_without_an_id())}
BRANCH_CHECKS.update({rule: (lambda: bool(request_body_sources())) for rule in BODY_ONLY})


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
    by_key, by_owner, _ = _graph()
    reverse: dict[tuple[str, str, int], set[str]] = {}
    for rule, keys in emitters().items():
        for key in keys:
            reverse.setdefault(key, set()).add(rule)
    seen: set[tuple[str, str, int]] = set()
    todo = [m.key for m in by_owner.get((class_name, method), ())]
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


def empty_stubs() -> set[tuple[str, str]]:
    """(class, method) of the methods that are only `return Optional.empty();` in every overload: a compatibility
    entry that decides nothing."""
    _, by_owner, _ = _graph()
    return {key for key, found in by_owner.items()
            if key[1] != "<init>" and all(re.sub(r"\s+", "", m.body) == "returnOptional.empty();" for m in found)}


def serves_only_not_wired(class_name: str, method: str) -> bool:
    """True for a detector entry point whose every rule id the catalogue marks not wired: no hook needs it."""
    ids = ids_reported_by(class_name, method)
    return bool(ids) and ids <= rule_catalogue.not_wired().keys()
