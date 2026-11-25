import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("catalog_check", Path(__file__).resolve().parents[1] / "check-vulhub-java-coverage.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogMatrixTest(unittest.TestCase):
    def test_only_exact_matrix_rows_supply_inventory_evidence(self):
        paths = ["app/one/README.md", "app/one-more/README.md", "app/two/README.md"]
        with tempfile.TemporaryDirectory() as work:
            ledger = Path(work) / "ledger.md"
            ledger.write_text(
                "## Source Path Coverage Matrix\n"
                "- [x] `app/one-more/README.md`\n"
                "- [ ] `app/two/README.md` ([candidate](#candidates))\n"
                "- [x] `app/one-more/README.md`\n"
                "- [x] `app/old/README.md`\n"
                "## Candidates\n- [ ] `app/one` mentions `app/one/README.md`\n- [ ] `app/one-more`\n- [ ] `app/two`\n")
            self.assertEqual(set(catalog.matrix_errors(paths, ledger)), {
                "Missing matrix row: app/one/README.md", "Duplicate matrix row: app/one-more/README.md",
                "Stale matrix row: app/old/README.md", "Matrix and candidate status disagree: app/one-more/README.md"})
