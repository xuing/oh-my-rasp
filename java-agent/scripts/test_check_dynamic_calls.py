"""Unit tests for check-dynamic-calls.py. No JDK needed: class files are assembled from bytes here.

The parser was also compared against `javap -c -p -v` on every class of the four agent JARs
(see the commit that added the tool); these tests keep the corner cases it found from regressing.
"""
import contextlib
import importlib.util
import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_dynamic_calls", HERE / "check-dynamic-calls.py")
cdc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cdc
spec.loader.exec_module(cdc)

LAMBDA = "java/lang/invoke/LambdaMetafactory.metafactory"
CONCAT = "java/lang/invoke/StringConcatFactory.makeConcatWithConstants"
RECORD = "java/lang/runtime/ObjectMethods.bootstrap"
SWITCH = "java/lang/runtime/SwitchBootstraps.typeSwitch"
CONDY = "java/lang/invoke/ConstantBootstraps.invoke"


class ClassBuilder:
    """Just enough of the class-file format: a constant pool, methods with raw code, BootstrapMethods."""

    def __init__(self, name: str):
        self.pool: list[bytes] = []
        self.slots = 1
        self.cache: dict[tuple, int] = {}
        self.methods: list[tuple[int, int, bytes]] = []
        self.bootstraps: list[int] = []
        self.this_class = self.cls(name)

    def _add(self, key: tuple, body: bytes, slots: int = 1) -> int:
        if key not in self.cache:
            self.pool.append(body)
            self.cache[key] = self.slots
            self.slots += slots
        return self.cache[key]

    def utf8(self, text: str) -> int:
        raw = text.encode()
        return self._add(("u", text), b"\x01" + struct.pack(">H", len(raw)) + raw)

    def cls(self, name: str) -> int:
        return self._add(("c", name), b"\x07" + struct.pack(">H", self.utf8(name)))

    def long(self, value: int) -> int:
        return self._add(("j", value), b"\x05" + struct.pack(">q", value), slots=2)

    def nat(self, name: str, desc: str) -> int:
        return self._add(("n", name, desc), b"\x0c" + struct.pack(">HH", self.utf8(name), self.utf8(desc)))

    def handle(self, owner: str, name: str) -> int:
        ref = self._add(("m", owner, name), b"\x0a" + struct.pack(">HH", self.cls(owner), self.nat(name, "()V")))
        return self._add(("h", owner, name), b"\x0f" + struct.pack(">BH", 6, ref))

    def bootstrap(self, qualified: str) -> int:
        owner, _, name = qualified.rpartition(".")
        self.bootstraps.append(self.handle(owner, name))
        return len(self.bootstraps) - 1

    def indy(self, qualified: str) -> int:
        return self._add(("i", len(self.bootstraps), qualified),
                         b"\x12" + struct.pack(">HH", self.bootstrap(qualified), self.nat("run", "()V")))

    def condy(self, qualified: str) -> int:
        return self._add(("d", len(self.bootstraps), qualified),
                         b"\x11" + struct.pack(">HH", self.bootstrap(qualified), self.nat("c", "I")))

    def method(self, name: str, desc: str, code: bytes) -> None:
        self.methods.append((self.utf8(name), self.utf8(desc), code))

    def build(self) -> bytes:
        code_attr = self.utf8("Code")
        boot_attr = self.utf8("BootstrapMethods")
        out = [struct.pack(">IHHH", 0xCAFEBABE, 0, 61, self.slots), *self.pool,
               struct.pack(">HHHH", 0x21, self.this_class, 0, 0), struct.pack(">H", 0)]  # flags, this, super, ifaces, fields
        out.append(struct.pack(">H", len(self.methods)))
        for name, desc, code in self.methods:
            body = struct.pack(">HHI", 1, 1, len(code)) + code + struct.pack(">HH", 0, 0)
            out.append(struct.pack(">HHHH", 1, name, desc, 1) + struct.pack(">HI", code_attr, len(body)) + body)
        if self.bootstraps:
            body = struct.pack(">H", len(self.bootstraps)) + b"".join(struct.pack(">HH", h, 0) for h in self.bootstraps)
            out.append(struct.pack(">HHI", 1, boot_attr, len(body)) + body)
        else:
            out.append(struct.pack(">H", 0))
        return b"".join(out)


def indy_insn(index: int) -> bytes:
    return b"\xba" + struct.pack(">HH", index, 0)


class ParseTest(unittest.TestCase):
    def test_lambda_site_names_class_method_and_bootstrap(self):
        c = ClassBuilder("a/Foo")
        c.method("run", "()V", indy_insn(c.indy(LAMBDA)) + b"\xb1")
        self.assertEqual(cdc.parse_class(c.build()), ("a/Foo", [("run()V", LAMBDA)]))

    def test_class_without_sites(self):
        c = ClassBuilder("a/Plain")
        c.method("run", "()V", b"\x00\xb1")
        self.assertEqual(cdc.parse_class(c.build()), ("a/Plain", []))

    def test_two_methods_and_a_shared_bootstrap_table(self):
        c = ClassBuilder("a/Two")
        c.method("<clinit>", "()V", indy_insn(c.indy(CONCAT)) + b"\xb1")
        c.method("f", "(I)V", indy_insn(c.indy(RECORD)) + indy_insn(c.indy(SWITCH)) + b"\xb1")
        _, sites = cdc.parse_class(c.build())
        self.assertEqual(sites, [("<clinit>()V", CONCAT), ("f(I)V", RECORD), ("f(I)V", SWITCH)])

    def test_switch_padding_is_aligned_to_the_code_array_not_the_file(self):
        for lead in range(4):  # 0..3 bytes before the switch opcode change the padding
            for kind in ("table", "lookup"):
                c = ClassBuilder("a/Sw")
                code = b"\x00" * lead
                pad = b"\x00" * ((4 - (lead + 1) % 4) % 4)
                if kind == "table":
                    code += b"\xaa" + pad + struct.pack(">iii", 0, 1, 3) + struct.pack(">iii", 0, 0, 0)
                else:
                    code += b"\xab" + pad + struct.pack(">ii", 0, 2) + struct.pack(">iiii", 1, 0, 2, 0)
                c.method("f", "()V", code + indy_insn(c.indy(LAMBDA)) + b"\xb1")
                self.assertEqual(cdc.parse_class(c.build())[1], [("f()V", LAMBDA)], (lead, kind))

    def test_long_constant_takes_two_pool_slots(self):
        c = ClassBuilder("a/Long")
        c.long(7)
        c.method("f", "()V", indy_insn(c.indy(LAMBDA)) + b"\xb1")
        self.assertEqual(cdc.parse_class(c.build())[1], [("f()V", LAMBDA)])

    def test_wide_iinc_and_wide_load_lengths(self):
        c = ClassBuilder("a/Wide")
        code = b"\xc4\x84\x01\x00\x00\x05" + b"\xc4\x15\x01\x00" + indy_insn(c.indy(LAMBDA)) + b"\xb1"
        c.method("f", "()V", code)
        self.assertEqual(cdc.parse_class(c.build())[1], [("f()V", LAMBDA)])

    def test_ldc_of_a_dynamic_constant_counts_as_a_site(self):
        c = ClassBuilder("a/Condy")
        index = c.condy(CONDY)
        c.method("f", "()V", b"\x13" + struct.pack(">H", index) + b"\xb1")  # ldc_w
        sites = cdc.parse_class(c.build())[1]
        self.assertEqual(sites, [("f()V", CONDY)])

    def test_garbage_is_rejected(self):
        with self.assertRaises(cdc.ClassFormatError):
            cdc.parse_class(b"not a class")
        with self.assertRaises(cdc.ClassFormatError):
            cdc.parse_class(struct.pack(">IHHH", 0xCAFEBABE, 0, 61, 4))

    def test_bootstrap_kinds(self):
        kinds = {LAMBDA: cdc.LAMBDA, "java/lang/invoke/LambdaMetafactory.altMetafactory": cdc.LAMBDA,
                 CONCAT: cdc.CONCAT, RECORD: cdc.RECORD, SWITCH: cdc.SWITCH,
                 "java/lang/runtime/SwitchBootstraps.enumSwitch": cdc.SWITCH, CONDY: cdc.OTHER,
                 "x/Y.z": cdc.OTHER}
        for bootstrap, kind in kinds.items():
            self.assertEqual(cdc.Site("l", "c", "m()V", bootstrap).kind, kind, bootstrap)


def site(cls, kind_bootstrap, method="m()V", line="java17"):
    return cdc.Site(line, cls, method, kind_bootstrap)


class CompareTest(unittest.TestCase):
    base = {"a/Foo": {"lambda": 1}}

    def test_same_counts_pass(self):
        self.assertEqual(cdc.compare(self.base, [site("a/Foo", LAMBDA)]), [])

    def test_fewer_sites_pass(self):
        self.assertEqual(cdc.compare(self.base, []), [])

    def test_extra_lambda_fails_and_names_class_method_and_construct(self):
        found = cdc.compare(self.base, [site("a/Foo", LAMBDA), site("a/Foo", LAMBDA, "hook(Ljava/lang/String;)V")])
        self.assertEqual(len(found), 1)
        for text in ("a/Foo", "hook(Ljava/lang/String;)V", "lambda or method reference", "allows 1"):
            self.assertIn(text, found[0])

    def test_class_missing_from_baseline_fails(self):
        found = cdc.compare(self.base, [site("a/New", RECORD, "toString()Ljava/lang/String;")])
        self.assertEqual(len(found), 1)
        self.assertIn("not in the baseline", found[0])
        self.assertIn("record", found[0])

    def test_switch_and_other_are_gated(self):
        self.assertEqual(len(cdc.compare({}, [site("a/S", SWITCH)])), 1)
        self.assertEqual(len(cdc.compare({}, [site("a/O", CONDY)])), 1)

    def test_string_concat_is_never_a_failure(self):
        self.assertEqual(cdc.compare({}, [site("a/Concat", CONCAT)] * 5), [])

    def test_one_kind_cannot_borrow_another_kinds_allowance(self):
        self.assertEqual(len(cdc.compare(self.base, [site("a/Foo", LAMBDA), site("a/Foo", RECORD)])), 1)

    def test_summarize_counts_per_class_and_kind_in_stable_order(self):
        table = cdc.summarize([site("b/B", CONCAT), site("a/A", LAMBDA), site("a/A", LAMBDA), site("a/A", RECORD)])
        self.assertEqual(table, {"a/A": {"lambda": 2, "record": 1}, "b/B": {"string-concat": 1}})
        self.assertEqual(list(table), ["a/A", "b/B"])


def jar_with(path: Path, classes: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        for name, data in classes.items():
            archive.writestr(name + ".class", data)


def class_with(name: str, *bootstraps: str) -> bytes:
    c = ClassBuilder(name)
    c.method("f", "()V", b"".join(indy_insn(c.indy(b)) for b in bootstraps) + b"\xb1")
    return c.build()


class CommandTest(unittest.TestCase):
    """The whole command against fake JARs laid out the way --build-root expects."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.baseline = self.root / "baseline.json"
        self.builds = {"java8": "agent-java8/libs/ohmyrasp-agent-java8.jar",
                       "java11": "agent-java11/libs/ohmyrasp-agent-java11.jar",
                       "java17": "agent-java17/libs/ohmyrasp-agent-java17.jar",
                       "jdk25": "agent-jdk25/libs/ohmyrasp-agent.jar"}

    def build(self, **classes_by_line):
        for line, relative in self.builds.items():
            jar_with(self.root / relative, classes_by_line.get(line, {}))

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cdc.main(["--build-root", str(self.root), "--baseline", str(self.baseline), *args])
        return code, out.getvalue(), err.getvalue()

    def test_update_then_check_passes_and_primary_line_is_not_gated(self):
        self.build(java17={"a/Foo": class_with("a/Foo", LAMBDA, CONCAT)}, jdk25={"a/P": class_with("a/P", RECORD)})
        self.assertEqual(self.run_cli("--update")[0], 0)
        baseline = json.loads(self.baseline.read_text())["lines"]
        self.assertEqual(baseline["java17"], {"a/Foo": {"lambda": 1, "string-concat": 1}})
        self.assertEqual(baseline["java8"], {})
        self.build(java17={"a/Foo": class_with("a/Foo", LAMBDA, CONCAT)},
                   jdk25={"a/P": class_with("a/P", RECORD, RECORD, LAMBDA)})  # primary line grew: still fine
        code, out, _ = self.run_cli("--check")
        self.assertEqual(code, 0, out)
        self.assertIn("string-concat=1 (reported, not gated)", out)
        self.assertIn("jdk25: primary line, recorded but not gated", out)

    def test_check_fails_for_a_new_lambda_with_actionable_message(self):
        self.build(java11={"a/Foo": class_with("a/Foo")})
        self.run_cli("--update")
        self.build(java11={"a/Foo": class_with("a/Foo", LAMBDA)})
        code, _, err = self.run_cli("--check")
        self.assertEqual(code, 1)
        for text in ("java11", "a/Foo", "f()V", "lambda or method reference", "anonymous class", "--update", "commit"):
            self.assertIn(text, err)

    def test_shaded_classes_are_skipped(self):
        self.build(java8={cdc.SHADED_PREFIX + "asm/X": class_with(cdc.SHADED_PREFIX + "asm/X", LAMBDA)})
        self.assertEqual(self.run_cli("--update")[0], 0)
        self.assertEqual(json.loads(self.baseline.read_text())["lines"]["java8"], {})

    def test_missing_jar_is_a_clear_error(self):
        code, _, err = self.run_cli("--check")
        self.assertEqual(code, 2)
        self.assertIn("build them first", err)

    def test_default_mode_lists_every_site_with_four_columns(self):
        self.build(java8={"a/Foo": class_with("a/Foo", LAMBDA, LAMBDA)})
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        rows = [line.split("\t") for line in out.splitlines()]
        self.assertEqual(rows, [["java8", "a/Foo", "f()V", LAMBDA]] * 2)


if __name__ == "__main__":
    unittest.main()
