#!/usr/bin/env python3
"""python -I check_service_review_install.py INSTALLED_ROOT CHECK_ROOT."""
import json
from pathlib import Path
import sys
import unittest

installed,checks=(Path(p).resolve(strict=True) for p in sys.argv[1:])
if (checks/'vfy').exists():raise SystemExit('CHECK_ROOT must not contain source vfy')
sys.path[:0]=[str(installed),str(checks)]
from vfy import service_review
if not Path(service_review.__file__).resolve().is_relative_to(installed):
    raise SystemExit('Wrong installed paid review origin')
print(json.dumps({'installed_origin':service_review.__file__,'identity':service_review.identity(),
    'python':sys.version,'scope':'fresh synthetic adoption, observation, accounting and action authorization controls'},sort_keys=True),flush=True)
# The legacy purity test inspects a source path; inspect the installed source.
from tests import test_authorization
test_authorization.REPO_ROOT=installed
suite=unittest.defaultTestLoader.loadTestsFromNames(['tests.test_service_review','tests.test_service_adoption','tests.test_service_tests',
    'tests.test_service_attempt','tests.test_authorization'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
