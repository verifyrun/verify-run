"""Public report distinguishes runtime observations from unobserved checker facts."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from tests.test_cli import _Workspace, _case, CLI_DIR
from vfy import store
from vfy.errors import StoreCommitConflict


class PublicExecutionReport(unittest.TestCase):
    def cases(self):
        path = Path(__file__).resolve().parent.parent / 'fixtures/consumer-interface/execution-report-v1.json'
        return json.loads(path.read_text())['cases']

    def test_real_success_refusal_recording_and_unknown_paths(self):
        for row in self.cases():
            with self.subTest(case=row['case']):
                case = _case(CLI_DIR / 'run_allow_exit_zero.json')
                with _Workspace(tree=case['tree'], template=case['template']) as workspace:
                    if row['case'] == 'checker_exits_65':
                        (workspace.root / 'bin/ok.sh').write_text('#!/bin/sh\nexit 65\n')
                    if row['case'] == 'hold':
                        (workspace.root / 'ci/last-test-result.sh').unlink()
                    def invoke():
                        return workspace.cli('--json', '--execution-report', 'run',
                                             '--identity', 'branch=main', '--', 'bin/ok.sh')
                    if row['case'] == 'recording_failure':
                        with patch.object(store.LocalStore, 'put_record', side_effect=StoreCommitConflict('test')):
                            code, out, err = invoke()
                        self.assertEqual(code, 14)
                    elif row['case'] == 'unexpected_failure':
                        with patch('vfy.cli.workflow.run', side_effect=RuntimeError('test')):
                            code, out, err = invoke()
                        self.assertEqual(code, 1)
                    else:
                        code, out, err = invoke()
                    body = json.loads(out)
                    report = body['execution_report']
                    for key, expected in row.items():
                        if key != 'case':
                            self.assertEqual(report[key], expected, (out, err))
                    self.assertEqual(report['version'], 1)
                    self.assertEqual(report['checker_execution'], 'not_observed')
                    self.assertEqual(report['context_refusal'], 'not_observed')
                    self.assertEqual(report['trust_policy'], 'supplied_snapshot')
                    self.assertFalse(report['automatic_retry_permitted'])

    def test_option_requires_json_run(self):
        with _Workspace() as workspace:
            for args in [('--execution-report','run','--','/bin/true'),
                         ('--execution-report','--json','init')]:
                self.assertEqual(workspace.cli(*args)[0], 2)

    def test_recording_loss_does_not_invite_retry_or_invent_checker_evidence(self):
        from vfy.errors import SigningKeyInvalid
        variants = [('issue', 'unavailable'), ('preserve', 'inline_uncommitted'),
                    ('unexpected', 'unknown')]
        for variant, expected in variants:
            with self.subTest(variant=variant):
                case = _case(CLI_DIR / 'run_allow_exit_zero.json')
                with _Workspace(tree=case['tree'], template=case['template']) as workspace:
                    program = workspace.root / 'bin/ok.sh'
                    program.write_text('#!/bin/sh\nprintf effect >> effect-marker\n')
                    from contextlib import ExitStack
                    with ExitStack() as stack:
                        if variant == 'issue':
                            stack.enter_context(patch('vfy.runner.receipt_module.issue_receipt',
                                                      side_effect=SigningKeyInvalid('test')))
                        else:
                            error = RuntimeError('test') if variant == 'unexpected' else StoreCommitConflict('test')
                            stack.enter_context(patch.object(store.LocalStore, 'put_record', side_effect=error))
                            if variant == 'preserve':
                                stack.enter_context(patch.object(store.LocalStore, 'preserve_unrecorded',
                                                                  side_effect=StoreCommitConflict('test')))
                        code, out, err = workspace.cli('--json','--execution-report','run',
                                                       '--identity','branch=main','--','bin/ok.sh')
                    report = json.loads(out)['execution_report']
                    self.assertEqual((workspace.root/'effect-marker').read_text(), 'effect')
                    self.assertEqual(report['receipt_availability'], expected)
                    self.assertEqual(report['nonce_consumption'], 'unknown' if variant == 'unexpected' else 'consumed')
                    self.assertEqual(report['recovery'], 'reconcile_before_new_request')
                    self.assertEqual(report['checker_execution'], 'not_observed')
                    self.assertFalse(report['automatic_retry_permitted'])
                    self.assertEqual(len(workspace.consumed()), 1)

    def test_failed_process_start_still_consumes_authority(self):
        case = _case(CLI_DIR / 'run_allow_exit_zero.json')
        with _Workspace(tree=case['tree'], template=case['template']) as workspace:
            (workspace.root/'bin/ok.sh').write_text('#!/nonexistent-interface-interpreter\n')
            code, out, err = workspace.cli('--json','--execution-report','run',
                                           '--identity','branch=main','--','bin/ok.sh')
            report = json.loads(out)['execution_report']
            self.assertEqual(code, 13)
            self.assertEqual(report['launcher_execution'], 'not_started')
            self.assertEqual(report['nonce_consumption'], 'consumed')
            self.assertEqual(report['receipt_availability'], 'committed')
