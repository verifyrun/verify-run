"""Successor-only harness; historical conformance test bytes remain unchanged.

Make only the historical mutation test's disposable fixture copy writable. The
test subject and historical kit stay read-only. All assertions are unchanged.
Run from the frozen source root with its selected Python and -B.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path.cwd()))
from tests.test_conformance import ManifestIntegrityIsEnforced
from frozen_fixture_permissions import make_disposable_writable

_original_setup = ManifestIntegrityIsEnforced.setUp


def _writable_disposable_copy(self):
    _original_setup(self)
    make_disposable_writable(self.copy, Path(self._directory.name))


ManifestIntegrityIsEnforced.setUp = _writable_disposable_copy
suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
