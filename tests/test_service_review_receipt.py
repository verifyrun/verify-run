"""Read-only retained receipt verification against fresh synthetic producer vectors."""
import json
import unittest
from unittest.mock import patch
from tests import test_service_review as fixtures
from vfy import child_ledger as m, service_review_receipt as v

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ReviewTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.reserve();self.receipt=self.f.review()
        self.args=dict(receipt_bytes=m.raw(self.receipt),trace_bytes=(self.f.pool.root/'reviews'/m.sha(self.f.raw)/'TRACE.json').read_bytes(),
            request_bytes=self.f.raw,ticket_bytes=m.raw(self.f.ticket),policy_bytes=m.raw(self.f.policy),
            owner_trust=self.f.owner.trust,expected_owner_issuer=self.f.owner.issuer,
            limits=dict(input_bytes=8000000,trace_entries=3000))

    def test_historical_correspondence_without_files_keys_or_runtime_calls(self):
        with patch.object(m,'read_file',side_effect=AssertionError('no filesystem reads')):
            result=v.verify_receipt(**self.args)
        self.assertEqual(result['state'],'VERIFIED_HISTORICAL_REVIEW_RECEIPT')
        self.assertEqual(result['run_result']['state'],'OBSERVED_CANDIDATE')
        self.assertFalse(result['current_source_checked']);self.assertFalse(result['authority_granted'])
        self.assertEqual(result['charged'],self.receipt['body']['charged'])

    def test_every_selected_raw_input_tamper_refused(self):
        for key in ('receipt_bytes','trace_bytes','request_bytes','ticket_bytes','policy_bytes'):
            with self.subTest(key=key):
                with self.assertRaises(Exception):v.verify_receipt(**dict(self.args,**{key:b'{}'}))

    def test_independent_owner_selection_refused(self):
        for change in [dict(owner_trust={}),dict(expected_owner_issuer='OTHER')]:
            with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,**change))

    def signed(self,**changes):
        b=dict(self.receipt['body'],**changes)
        return m.raw(m.envelope(b,self.f.owner.key,self.f.owner.issuer))

    def test_signed_wrong_charge_or_identity_refused(self):
        changes=[dict(charged=dict(read_bytes=0,read_calls=0)),dict(ticket_sha256='f'*64),
                 dict(request_sha256='f'*64),dict(source_relation='MISMATCH'),
                 dict(review_identity={'profile':'wrong','source_sha256':'f'*64}),
                 dict(reserved=dict(read_bytes=1,read_calls=1,retained_bytes=65536))]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,receipt_bytes=self.signed(**change)))

    def test_scope_flags_cannot_be_promoted(self):
        for changes in [dict(full_cost='KNOWN'),dict(service_execution=True),dict(automatic_retry=True),
                        dict(full_reservation_retained=False),dict(exclusions=[])]:
            with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,receipt_bytes=self.signed(**changes)))

    def test_input_and_trace_limits(self):
        for limits in [dict(input_bytes=1,trace_entries=3000),dict(input_bytes=8000000,trace_entries=1)]:
            with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,limits=limits))

    def test_signed_unknown_is_never_current_acceptance(self):
        b=dict(self.receipt['body'],state='UNKNOWN_HOLD_RETAINED',run_result=fixtures.r._unknown(),reason='INTERRUPTED')
        receipt=m.raw(m.envelope(b,self.f.owner.key,self.f.owner.issuer))
        result=v.verify_receipt(**dict(self.args,receipt_bytes=receipt))
        self.assertEqual(result['recorded_review_state'],'UNKNOWN_HOLD_RETAINED')
        self.assertEqual(result['run_result']['state'],'UNKNOWN')
        self.assertFalse(result['automatic_retry'])

    def test_wrong_signed_ticket_selection_refused(self):
        body=json.loads(self.args['ticket_bytes'])['body'];body['entries'][-1]['request_sha256']='f'*64
        ticket=m.raw(m.envelope(body,self.f.owner.key,self.f.owner.issuer))
        receipt=self.signed(ticket_sha256=m.sha(ticket))
        with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,ticket_bytes=ticket,receipt_bytes=receipt))

if __name__=='__main__':unittest.main()

class ExtraReceiptControls(unittest.TestCase):
    setUp=ReceiptTests.setUp
    signed=ReceiptTests.signed

    def test_noncanonical_selected_ticket_is_not_exact(self):
        raw=json.dumps(json.loads(self.args['ticket_bytes']),indent=2).encode()
        with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,ticket_bytes=raw))

    def test_authentic_resigned_trace_with_wrong_input_binding_refused(self):
        trace=json.loads(self.args['trace_bytes']);trace[0]['sha256']='f'*64;raw=m.raw(trace)
        receipt=self.signed(trace_sha256=m.sha(raw))
        with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,trace_bytes=raw,receipt_bytes=receipt))

    def test_signed_failed_receipt_cannot_undercount_partial_trace(self):
        receipt=self.signed(state='UNKNOWN_HOLD_RETAINED',run_result=fixtures.r._unknown(),reason='FAILED',
                            charged=dict(read_bytes=1,read_calls=1))
        with self.assertRaises(m.Refused):v.verify_receipt(**dict(self.args,receipt_bytes=receipt))

    def test_original_source_can_be_absent_without_reexecution(self):
        # Deny every payload file read; only supplied bytes are needed.
        from pathlib import Path
        with patch.object(Path,'read_bytes',side_effect=AssertionError('hidden file read')):
            result=v.verify_receipt(**self.args)
        self.assertFalse(result['current_source_checked'])
        self.assertFalse(result['settlement_verified'])
