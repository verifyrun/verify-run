"""Executable current-contract gaps; passing means gap is reproduced, not solved."""
import json
import unittest
from unittest.mock import patch
from tests import test_service_adoption as fixtures
from vfy import service_adoption as a

class PreparationContractGap(unittest.TestCase):
    def test_preparation_is_outside_shared_reservation(self):
        f=fixtures.AdoptionTests()
        # Existing fixture performs real copy creation + evidence preparation
        # before attach/reserve. Observe whether preparation asked the pool.
        with patch.object(a.AdoptionPool, 'reserve', wraps=a.AdoptionPool.reserve) as reserve:
            # Avoid fixture's later reserve so only preparation is measured.
            with patch.object(a.AdoptionPool, 'attach', side_effect=RuntimeError('after-preparation')):
                with self.assertRaisesRegex(RuntimeError,'after-preparation'):f.setUp()
            self.addCleanup(f.doCleanups)
            reserve.assert_not_called()
        self.assertTrue((f.root/'PLAN.json').is_file())
        fixture=json.loads((f.root/'FIXTURE.json').read_bytes())
        self.assertFalse(fixture['preparation']['shared_pool_charged'])
