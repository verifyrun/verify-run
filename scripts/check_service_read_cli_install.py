#!/usr/bin/env python3
"""Installed-unit harness; public subprocess consumer is a separate stdlib-only file."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

checks,installed,executable,client=(Path(p).resolve(strict=True) for p in sys.argv[1:])
sys.path.insert(0,str(checks))
from vfy import service_read_cli
assert Path(service_read_cli.__file__).resolve().is_relative_to(installed)
print(json.dumps(dict(installed_origin=str(Path(service_read_cli.__file__).resolve()),executable=str(executable))),flush=True)
from tests.test_service_read_cli import ReadCliTests
fixture=ReadCliTests()
try:
    fixture.setUp()
    folder=fixture.f.f.f.f.base
    receipt=folder/'RECEIPT_REQUEST.json';reconcile=folder/'RECONCILE_REQUEST.json'
    receipt.write_text(json.dumps(fixture.receipt));reconcile.write_text(json.dumps(fixture.reconcile))
    subprocess.run([sys.executable,'-I','-B',str(client),str(executable),str(receipt),str(reconcile)],check=True)
finally:fixture.doCleanups()
suite=unittest.defaultTestLoader.loadTestsFromNames(['tests.test_service_read_cli','tests.test_cli','tests.test_service_review_receipt'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
