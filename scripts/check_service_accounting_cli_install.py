#!/usr/bin/env python3
"""Installed-origin tests; lifecycle calls use the real public console subprocess."""
import os
from pathlib import Path
import sys
import unittest
checks, installed, executable = (Path(p).resolve(strict=True) for p in sys.argv[1:])
sys.path.insert(0,str(checks))
from vfy import service_accounting_cli
assert Path(service_accounting_cli.__file__).resolve().is_relative_to(installed)
print('Installed module:',Path(service_accounting_cli.__file__).resolve(),flush=True)
os.environ['VFY_SESSION_TEST_EXECUTABLE']=str(executable)
suite=unittest.defaultTestLoader.loadTestsFromNames([
    'tests.test_service_accounting_cli.SessionTests', 'tests.test_service_read_cli',
    'tests.test_cli', 'tests.test_service_attempt'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
