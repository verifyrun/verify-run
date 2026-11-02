"""Actual signed synthetic fixture accounting; no subprocess execution claim."""
import json
import unittest
from tests import test_service_tests as fixtures
from vfy import child_ledger as m, service_test_successor as s


class SuccessionTests(unittest.TestCase):
    task = b'PUBLIC SYNTHETIC TASK: preserve the two declared requirements'

    def observation(self, revision=1, parent=None, *, legacy=False, change=None, fail=False):
        f = fixtures.ObservationTests(); f.setUp()
        self.addCleanup(f.doCleanups)
        action = f.f.action
        def declared():
            q, raw = action()
            p = json.loads(raw)
            if not legacy:
                p[s.FIELD] = s.binding(self.task, revision, parent)
            if change:
                change(p)
            return q, m.raw(p)
        f.f.action = declared
        args = {} if not fail else dict(events=[{'id':'suite.Case.test_one','outcome':'failure'},
                                                {'id':'suite.Case.test_two','outcome':'success'}], successful=False, exit=1)
        record = f.observed(**args)
        return (f.checker, f.args), record

    def check(self, links, **kw):
        return s.check_chain(links, task_bytes=self.task,
                             expected_task_sha256=kw.get('task_sha', m.sha(self.task)),
                             destination_predecessor_sha256=kw.get('destination'))

    def test_authenticated_failure_then_success_same_task(self):
        first, r = self.observation(fail=True)
        second, _ = self.observation(2, m.digest(r))
        result = self.check([first, second], destination=m.digest(r))
        with self.assertRaisesRegex(m.Refused, 'DESTINATION'): self.check([first, second], destination='f'*64)
        self.assertEqual([v['state'] for v in result['observations']],
            ['OBSERVED_SELECTED_CASES_NON_SUCCESS', 'OBSERVED_SELECTED_CASES_SUCCESS'])
        self.assertFalse(result['authority_granted'])
        self.assertEqual(result['repair_causality'], 'UNESTABLISHED')
        self.assertEqual(result['result_sha256'], m.digest({k:v for k,v in result.items() if k != 'result_sha256'}))

    def test_wrong_parent_and_legacy_refuse(self):
        first, _ = self.observation()
        second, _ = self.observation(2, 'f'*64)
        with self.assertRaisesRegex(m.Refused, 'PREDECESSOR'): self.check([first, second])
        legacy, _ = self.observation(legacy=True)
        with self.assertRaisesRegex(m.Refused, 'UNESTABLISHED'): self.check([legacy])

    def test_signed_different_examiner_and_task_refuse(self):
        first, r = self.observation()
        second, _ = self.observation(2, m.digest(r), change=lambda p:p.update(examiner={'tree':'other'}))
        with self.assertRaisesRegex(m.Refused, 'EXAMINER'): self.check([first, second])
        other, _ = self.observation(change=lambda p:p[s.FIELD].update(task_sha256='f'*64))
        with self.assertRaisesRegex(m.Refused, 'PREDECESSOR'): self.check([other])
        with self.assertRaisesRegex(m.Refused, 'SELECTED_TASK'): self.check([first], task_sha='f'*64)

    def test_unsigned_preview_edit_and_changed_report_refuse(self):
        link, _ = self.observation()
        for key in ('preview_bytes', 'stdout_bytes', 'accounting_snapshot_bytes'):
            bad = dict(link[1]); bad[key] = b'{}'
            with self.assertRaisesRegex(m.Refused, 'UNAUTHENTICATED'): self.check([(link[0], bad)])

    def test_closed_binding_types_and_chain_bounds(self):
        for revision in (True, 0, 65):
            with self.assertRaises(m.Refused): s.binding(self.task, revision, None)
        with self.assertRaises(m.Refused): self.check([])
        link, _ = self.observation(change=lambda p:p[s.FIELD].update(authority_granted=0))
        with self.assertRaises(m.Refused): self.check([link])
        with self.assertRaises(m.Refused): self.check([(object(), {})])


if __name__ == '__main__': unittest.main()
