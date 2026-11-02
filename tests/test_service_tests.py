"""Fresh signed synthetic named-observation controls, never retained real executions."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_service_attempt as attempt_fixtures
from vfy import child_ledger as m, service_tests as st


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=attempt_fixtures.ServiceTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.addCleanup(self.fixture.tearDown)
        self.f=self.fixture
        self.runner=b'SYNTHETIC_PINNED_RUNNER_NOT_EXECUTED'
        self.limits=dict(input_bytes=1000000,cases=20,requirements=10,retained_bytes=2000000)

    def observed(self, *, events=None, completed=True, successful=True, exit=0, changes=None):
        f=self.f;q,praw=f.action();p=json.loads(praw)
        q['resources']['output_bytes']=800;p['limits']=q['resources']
        self.requirements=m.raw({'schema':'vfy.service-requirements/1',
            'requirements':{'REQ-ONE':'Frozen examiner requirement one','REQ-TWO':'Frozen examiner requirement two'}})
        self.selection=dict(schema='vfy.service-test-selection/1',requirements_sha256=m.sha(self.requirements),
            source_sha256=m.digest(p['source']),examiner_sha256=m.digest(p['examiner']),environment_sha256=m.digest(p['environment']),
            adapter_sha256=p['adapter_sha256'],capture_sha256=p['capture_sha256'],runner_sha256=m.sha(self.runner),
            labels=p['labels'],case_ids=['suite.Case.test_one','suite.Case.test_two'],
            requirement_cases={'REQ-ONE':['suite.Case.test_one'],'REQ-TWO':['suite.Case.test_one','suite.Case.test_two']},
            authority_granted=False,automatic_retry=False)
        self.selection_bytes=m.raw(self.selection)
        p.update(test_selection_sha256=m.sha(self.selection_bytes),test_runner_sha256=m.sha(self.runner))
        praw=m.raw(p);q['preview_sha256']=m.sha(praw)
        root=Path(q['attempt_root']);(root/'PREVIEW.json').write_bytes(praw)
        a=(q,praw);ticket=f.admit(a);start=f.start(a);f.consume(ticket,a,start)
        if events is None:events=[dict(id=i,outcome='success') for i in self.selection['case_ids']]
        report=dict(schema='engineer.service-tests/1',preview_sha256=m.sha(praw),events=events,
            tests_run=len(events),completed=completed,successful=successful)
        if changes:report.update(changes)
        stdout=json.dumps(report,indent=1).encode();stderr=b'diagnostics only'
        result=dict(preview=m.sha(praw),state='PROCESS_OBSERVED',exit=exit,limit_failure=None,
            inputs_unchanged=True,post_execution={'source':p['source'],'examiner':p['examiner']},
            stdout_sha256=m.sha(stdout),stderr_sha256=m.sha(stderr),wall_seconds=0.01)
        result_raw=json.dumps(result).encode()
        for name,raw in [('RESULT.json',result_raw),('stdout.bin',stdout),('stderr.bin',stderr)]:m.fresh(root/name,raw)
        f.pool.settle(ticket,result_bytes=result_raw,stdout_bytes=stdout,stderr_bytes=stderr,recorded_at='SYNTHETIC')
        self.args=dict(preview_bytes=praw,start_bytes=start,result_bytes=result_raw,
            stdout_bytes=stdout,stderr_bytes=stderr,accounting_snapshot_bytes=f.pool.snapshot(),request_sha256=m.sha(m.raw(q)))
        self.checker=self.new_checker()
        return self.checker.check(**self.args)

    def new_checker(self, **kw):
        args=dict(selection_bytes=self.selection_bytes,requirements_bytes=self.requirements,runner_bytes=self.runner,limits=self.limits)
        args.update(kw)
        return st.TestObservationChecker(self.f.pool,**args)

    def assert_unknown(self, record):
        self.assertEqual(record['state'],'UNKNOWN')
        self.assertFalse(record['all_selected_cases_reported_success'])

    def test_exact_success_maps_frozen_requirements_without_semantic_acceptance(self):
        r=self.observed()
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_SUCCESS')
        self.assertEqual(set(r['requirements']),{'REQ-ONE','REQ-TWO'})
        self.assertEqual(r['semantic_acceptance'],'UNESTABLISHED')
        self.assertFalse(r['authority_granted'])
        self.assertEqual(r['refs']['stdout_bytes'],m.sha(self.args['stdout_bytes']))

    def test_missing_case_unknown(self):
        self.assert_unknown(self.observed(events=[{'id':'suite.Case.test_one','outcome':'success'}]))

    def test_extra_case_unknown(self):
        self.assert_unknown(self.observed(events=[{'id':'suite.Case.test_one','outcome':'success'},
            {'id':'suite.Case.test_two','outcome':'success'},{'id':'suite.Other.test_extra','outcome':'success'}]))

    def test_duplicate_success_unknown(self):
        self.assert_unknown(self.observed(events=[{'id':'suite.Case.test_one','outcome':'success'}]*2))

    def test_incomplete_unknown(self):self.assert_unknown(self.observed(completed=False))

    def test_skip_nonpassing_even_successful(self):
        r=self.observed(events=[{'id':'suite.Case.test_one','outcome':'skip'},{'id':'suite.Case.test_two','outcome':'success'}])
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_NON_SUCCESS')
        self.assertFalse(r['all_selected_cases_reported_success'])

    def test_expected_failure_nonpassing(self):
        r=self.observed(events=[{'id':'suite.Case.test_one','outcome':'expected_failure'},{'id':'suite.Case.test_two','outcome':'success'}])
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_NON_SUCCESS')

    def test_error_nonpassing(self):
        r=self.observed(events=[{'id':'suite.Case.test_one','outcome':'error'},{'id':'suite.Case.test_two','outcome':'success'}],successful=False,exit=1)
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_NON_SUCCESS')

    def test_failure_nonpassing(self):
        r=self.observed(events=[{'id':'suite.Case.test_one','outcome':'failure'},{'id':'suite.Case.test_two','outcome':'success'}],successful=False,exit=1)
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_NON_SUCCESS')

    def test_unexpected_success_nonpassing(self):
        r=self.observed(events=[{'id':'suite.Case.test_one','outcome':'unexpected_success'},{'id':'suite.Case.test_two','outcome':'success'}],successful=False,exit=1)
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_NON_SUCCESS')

    def test_summary_lie_unknown(self):self.assert_unknown(self.observed(successful=False))
    def test_bool_count_unknown(self):self.assert_unknown(self.observed(changes={'tests_run':True}))
    def test_wrong_report_version_unknown(self):self.assert_unknown(self.observed(changes={'schema':'engineer.service-tests/2'}))
    def test_wrong_report_preview_unknown(self):self.assert_unknown(self.observed(changes={'preview_sha256':'f'*64}))
    def test_count_mismatch_unknown(self):self.assert_unknown(self.observed(changes={'tests_run':99}))
    def test_nonzero_cannot_pass_success_report(self):self.assert_unknown(self.observed(exit=1))

    def test_raw_evidence_tamper_or_missing_is_unknown(self):
        self.observed()
        for field in self.args:
            with self.subTest(field=field):
                args=dict(self.args);args[field]='f'*64 if field=='request_sha256' else b'{}'
                self.assert_unknown(self.checker.check(**args))

    def test_changed_selected_inputs_and_mapping_cannot_pass(self):
        self.observed()
        for field in ('source_sha256','examiner_sha256','environment_sha256','adapter_sha256','capture_sha256'):
            sel=dict(self.selection,**{field:'f'*64})
            c=self.new_checker(selection_bytes=m.raw(sel));self.assert_unknown(c.check(**self.args))
        sel=dict(self.selection,requirement_cases={'REQ-ONE':['suite.Case.test_two'],'REQ-TWO':['suite.Case.test_one']})
        self.assert_unknown(self.new_checker(selection_bytes=m.raw(sel)).check(**self.args))

    def test_unmapped_requirements_or_cases_rejected_before_check(self):
        self.observed()
        for mapping in ({'REQ-ONE':['suite.Case.test_one']},
                        {'REQ-ONE':['suite.Case.test_one'],'REQ-TWO':['suite.Case.test_one']},
                        {'REQ-ONE':[],'REQ-TWO':['suite.Case.test_one','suite.Case.test_two']}):
            with self.assertRaises(m.Refused):self.new_checker(selection_bytes=m.raw(dict(self.selection,requirement_cases=mapping)))

    def test_wrong_runner_or_frozen_requirements_rejected(self):
        self.observed()
        with self.assertRaises(m.Refused):self.new_checker(runner_bytes=b'changed runner')
        with self.assertRaises(m.Refused):self.new_checker(requirements_bytes=b'{}')

    def test_independent_input_case_and_requirement_limits(self):
        self.observed()
        for key in ('input_bytes','cases','requirements'):
            with self.subTest(limit=key):
                with self.assertRaises(m.Refused):self.new_checker(limits=dict(self.limits,**{key:1}))

    def test_exclusive_retention_signed_manifest_raw_bytes_and_pool_unchanged(self):
        self.observed();before=self.f.pool.snapshot();dest=self.f.base/'retained'
        receipt=self.checker.retain(dest,recorded_at='SYNTHETIC',**self.args)
        body=m.authenticate(receipt,self.f.old.trust)
        for name,sha in body['manifest'].items():self.assertEqual(m.sha((dest/name).read_bytes()),sha)
        self.assertEqual((dest/'stdout.bin').read_bytes(),self.args['stdout_bytes'])
        self.assertEqual(self.f.pool.snapshot(),before)
        with self.assertRaises(FileExistsError):self.checker.retain(dest,recorded_at='SYNTHETIC',**self.args)

    def test_retention_limit_refuses_before_writing(self):
        self.observed();c=self.new_checker(limits=dict(self.limits,retained_bytes=1));dest=self.f.base/'too-small'
        with self.assertRaises(m.Refused):c.retain(dest,recorded_at='SYNTHETIC',**self.args)
        self.assertFalse(dest.exists())

    def test_untrusted_or_unknown_accounting_cannot_pass(self):
        self.observed();record=json.loads(self.args['accounting_snapshot_bytes'])
        record['body']['entries'][0]['unknown']={'reason':'uncertain','recorded_at':'SYNTHETIC'}
        record['body']['entries'][0]['state']='UNKNOWN';record['body']['revision']+=1
        # Explicitly synthetic owner creates a valid UNKNOWN state, not real history rewriting.
        signed=m.envelope(record['body'],self.f.old.key,self.f.old.issuer)
        self.assert_unknown(self.checker.check(**dict(self.args,accounting_snapshot_bytes=m.raw(signed))))

    def test_signed_but_uncertain_post_execution_cannot_pass(self):
        self.observed()
        for change in ({'inputs_unchanged':False},{'post_execution':{'source':{},'examiner':{}}},
                       {'limit_failure':'output truncated'},{'exit':True}):
            with self.subTest(change=change):
                raw=json.dumps(dict(json.loads(self.args['result_bytes']),**change)).encode()
                state=json.loads(self.args['accounting_snapshot_bytes'])['body']
                state['entries'][0]['result']['result_sha256']=m.sha(raw)
                signed=m.envelope(state,self.f.old.key,self.f.old.issuer)
                args=dict(self.args,result_bytes=raw,accounting_snapshot_bytes=m.raw(signed))
                self.assert_unknown(self.checker.check(**args))

    def test_order_is_not_required_but_case_identity_is(self):
        r=self.observed(events=[{'id':'suite.Case.test_two','outcome':'success'},
            {'id':'suite.Case.test_one','outcome':'success'}])
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_SUCCESS')

    def test_uncertain_stdout_never_uses_console_fallback(self):
        self.observed()
        for raw in (b'OK', b'{}\n{}', b'{"events":[],"events":[]}', b'{"tests_run":NaN}',
                    b'log prefix\n'+self.args['stdout_bytes'], self.args['stdout_bytes'][:30]):
            with self.subTest(raw=raw[:30]):
                self.assert_unknown(self.checker.check(**dict(self.args,stdout_bytes=raw)))

    def test_unknown_report_outcome_or_extra_field(self):
        self.assert_unknown(self.observed(events=[{'id':'suite.Case.test_one','outcome':'passed'},
            {'id':'suite.Case.test_two','outcome':'success'}]))

    def test_retained_verification_tamper_and_missing_receipt(self):
        self.observed();dest=self.f.base/'retained'
        self.checker.retain(dest,recorded_at='SYNTHETIC',**self.args)
        r=self.checker.verify_retained(dest)
        self.assertEqual(r['state'],'OBSERVED_SELECTED_CASES_SUCCESS')
        (dest/'stdout.bin').write_bytes(b'changed')
        with self.assertRaises(m.Refused):self.checker.verify_retained(dest)
        (dest/'RECEIPT.json').unlink()
        with self.assertRaises(OSError):self.checker.verify_retained(dest)

    def load(self, **changes):
        f=self.f;snapshot=f.pool.snapshot()
        args=dict(snapshot_bytes=snapshot,expected_snapshot_sha256=m.sha(snapshot),expected_pool_root=str(f.old.root),
            expected_config_bytes=f.old.config_bytes,owner_trust=f.old.trust,child_trust=f.old.child_trust,
            selected_observer=f.old.observer,predecessor_snapshot_bytes=f.head,policy_bytes=f.kw['policy_bytes'],
            expected_child_trusts={})
        args.update(changes)
        return st.load_service_pool(**args)

    def test_readonly_loader_checks_existing_attempt_without_pool_io_or_key(self):
        self.observed();snapshot=self.f.pool.snapshot()
        # Capture independent inputs before making all pool file reads fail.
        with patch.object(self.f.pool,'snapshot',return_value=snapshot), patch.object(m,'read_file',side_effect=AssertionError('pool I/O forbidden')):
            loaded=self.load()
            self.assertEqual(loaded.snapshot(),snapshot)
            self.assertFalse(hasattr(loaded.owner,'key'))
            c=st.TestObservationChecker(loaded,selection_bytes=self.selection_bytes,
                requirements_bytes=self.requirements,runner_bytes=self.runner,limits=self.limits)
            self.assertEqual(c.check(**self.args)['state'],'OBSERVED_SELECTED_CASES_SUCCESS')
            for method in ('admit','consume','settle','mark_unknown','attach'):
                with self.assertRaises(m.Refused):getattr(loaded,method)()
            with self.assertRaises(m.Refused):c.retain(self.f.base/'readonly',recorded_at='TEST',**self.args)

    def test_readonly_loader_rejects_unselected_snapshot_trust_config_or_root(self):
        self.observed()
        for change in ({'expected_snapshot_sha256':'f'*64},{'expected_pool_root':'/wrong'},
                       {'expected_config_bytes':b'{}'},{'owner_trust':{}},{'child_trust':{}},
                       {'selected_observer':{}},{'policy_bytes':b'{}'},{'minimum_revision':999}):
            with self.subTest(change=change):
                with self.assertRaises((m.Refused,KeyError)):self.load(**change)

    def test_readonly_loader_managed_prefix(self):
        base=self.f.base/'managed-prefix';base.mkdir()
        old,managed,grant,kw=attempt_fixtures.managed_fixture(base)
        managed.apply_grant(m.raw(grant),recorded_at='TEST');self.f.bind(managed)
        from vfy import managed_capacity
        loaded=self.load(expected_child_trusts=kw['expected_child_trusts'],
            managed_legacy_snapshot_bytes=managed.legacy_bytes,selected_callback_identity=managed.callback,
            selected_managed_identity=managed_capacity.identity())
        self.assertEqual(loaded.snapshot(),self.f.pool.snapshot())
        self.assertEqual(loaded.verify_snapshot(loaded.snapshot())['used']['dispatch_slots'],1)


if __name__=='__main__':unittest.main()
