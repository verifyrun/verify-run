#!/usr/bin/env python3
"""python -I check_service_tests_install.py INSTALLED_ROOT CHECK_ROOT."""
import json
from pathlib import Path
import sys
import unittest

installed,checks=(Path(p).resolve(strict=True) for p in sys.argv[1:])
if (checks/'vfy').exists():raise SystemExit('CHECK_ROOT must not contain source vfy')
sys.path[:0]=[str(installed),str(checks)]
from vfy import service_tests
if not Path(service_tests.__file__).resolve().is_relative_to(installed):
    raise SystemExit('Wrong installed checker origin')
print(json.dumps({'installed_origin':service_tests.__file__,'checker_identity':service_tests.identity(),
    'python':sys.version,'scope':'synthetic checker and accounting controls'},sort_keys=True),flush=True)
suite=unittest.defaultTestLoader.loadTestsFromNames(['tests.test_service_tests','tests.test_service_attempt',
    'tests.test_common_capacity','tests.test_managed_capacity'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
