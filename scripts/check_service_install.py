#!/usr/bin/env python3
"""Run from any cwd: python -I check_service_install.py INSTALLED_ROOT TEST_ROOT.

Dependencies must already be installed in the selected interpreter. TEST_ROOT
contains only the supplied tests package. Never add a source checkout to sys.path.
"""
import json
from pathlib import Path
import sys
import unittest

installed, checks = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
if (checks/'vfy').exists():
    raise SystemExit('TEST_ROOT must not contain source vfy')
sys.path[:0] = [str(installed), str(checks)]
from vfy import service_attempt

origin = Path(service_attempt.__file__).resolve()
if not origin.is_relative_to(installed):
    raise SystemExit('Wrong installed module origin')
print(json.dumps({'installed_origin':str(origin), 'service_identity':service_attempt.identity(),
    'python':sys.version, 'fixture_scope':'FRESH_SYNTHETIC_ACCOUNTING_ONLY'},sort_keys=True),flush=True)
suite=unittest.defaultTestLoader.loadTestsFromNames([
    'tests.test_service_attempt','tests.test_common_capacity','tests.test_managed_capacity'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
