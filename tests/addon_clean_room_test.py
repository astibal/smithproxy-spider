"""Build-time guards for the clean-room addon compatibility boundary."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9_.-]+)")


def _requirement_names(path):
    names = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.partition("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQUIREMENT_NAME.match(line)
        if match:
            names.append(match.group(1).lower().replace("_", "-"))
    return names


class CleanRoomBoundaryTests(unittest.TestCase):
    def test_runtime_requirements_do_not_install_the_reference_product(self):
        for relative_path in (
            "deploy/requirements-addon.txt",
            "tests/requirements-addon.txt",
        ):
            with self.subTest(path=relative_path):
                names = _requirement_names(ROOT / relative_path)
                self.assertNotIn("mitmproxy", names)

    def test_runtime_requires_the_patched_brotli_decoder(self):
        requirements = (
            ROOT / "deploy/requirements-addon.txt"
        ).read_text(encoding="utf-8").splitlines()
        self.assertIn("Brotli>=1.2.1", requirements)

    def test_spider_runtime_never_imports_the_reference_package(self):
        violations = []
        for path in sorted((ROOT / "src").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported = [node.module or ""]
                else:
                    continue
                for module_name in imported:
                    if module_name == "mitmproxy" or module_name.startswith("mitmproxy."):
                        relative = path.relative_to(ROOT)
                        violations.append(
                            f"{relative}:{node.lineno}: {module_name}"
                        )
        self.assertEqual(violations, [])

    def test_source_tree_does_not_vendor_the_reference_package(self):
        violations = []
        for source_root in ("src", "external", "third_party", "vendor"):
            root = ROOT / source_root
            if not root.exists():
                continue
            for path in root.rglob("mitmproxy"):
                if path.is_dir():
                    violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])

    def test_worker_manifest_contains_only_spider_owned_modules(self):
        manifest = ROOT / "src/addon_worker_modules.txt"
        entries = [
            line.strip()
            for line in manifest.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(entries), len(set(entries)))
        for entry in entries:
            path = Path(entry)
            module_name = path.stem
            with self.subTest(module=entry):
                self.assertEqual(path.suffix, ".py")
                self.assertEqual(path.name, entry)
                self.assertRegex(module_name, r"^addon_[A-Za-z0-9_]+$")
                self.assertTrue((ROOT / "src" / entry).is_file())


if __name__ == "__main__":
    unittest.main()
