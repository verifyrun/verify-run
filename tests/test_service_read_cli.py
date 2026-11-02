"""Bounded public CLI protocol; disposable synthetic retained evidence only."""
import base64
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_service_review_receipt as receipts
from vfy import child_ledger as m, service_read_cli as c


def packed(raw):return dict(base64=base64.b64encode(raw).decode('ascii'),sha256=m.sha(raw))

class ReadCliTests(unittest.TestCase):
    def setUp(self):
        self.f=receipts.ReceiptTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.receipt=dict(schema='vfy.verify-service-receipt-request/1',
            inputs={k[:-6]:packed(v) for k,v in self.f.args.items() if k.endswith('_bytes')},
            module_sha256=c.RECEIPT_SHA256,owner_issuer=self.f.args['expected_owner_issuer'],
            limits=dict(input_bytes=8000000,trace_entries=3000,output_bytes=65536))
        self.receipt['inputs']['trust']=packed(m.raw(self.f.args['owner_trust']))
        a=self.f.f.f
        self.reconcile=dict(schema='vfy.reconcile-service-repair-request/1',root=str(a.root),
            inputs=dict(plan=packed((a.root/'PLAN.json').read_bytes()),trust=packed(m.raw(a.f.old.trust))),
            module_sha256=c.ADOPTION_SHA256,
            limits=dict(input_bytes=8000000,read_bytes=2000000,read_calls=1000,output_bytes=65536))

    def call(self,command,request,**changes):
        raw=m.raw(request);out=io.StringIO()
        kw=dict(command=command,request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out);kw.update(changes)
        code=c.run(**kw);return code,json.loads(out.getvalue())

    def test_receipt_exact_result_historical_no_source_reads(self):
        code,result=self.call('verify-service-receipt',self.receipt)
        self.assertEqual(code,0);self.assertEqual(result['result']['state'],'VERIFIED_HISTORICAL_REVIEW_RECEIPT')
        self.assertFalse(result['result']['current_source_checked'])
        self.assertFalse(result['authority_granted']);self.assertEqual(result['mode'],'HISTORICAL_RECEIPT')

    def test_reconcile_candidate_preserves_old_result_and_bytes(self):
        a=self.f.f.f;before={str(p):p.read_bytes() for p in a.root.rglob('*') if p.is_file()}
        code,result=self.call('reconcile-service-repair',self.reconcile)
        self.assertEqual(code,0);self.assertEqual(result['result']['state'],'OBSERVED_CANDIDATE')
        self.assertEqual(before,{str(p):p.read_bytes() for p in a.root.rglob('*') if p.is_file()})
        self.assertGreater(result['read_usage']['read_bytes'],0)

    def test_unknown_not_transport_failure_or_readiness(self):
        (self.f.f.f.root/'copy/app/a.py').write_bytes(b'later edit')
        code,result=self.call('reconcile-service-repair',self.reconcile)
        self.assertEqual(code,0);self.assertEqual(result['result']['state'],'UNKNOWN')
        self.assertFalse(result['automatic_retry'])

    def test_each_receipt_input_tamper_and_unselected_module_refused(self):
        for name in self.receipt['inputs']:
            req=json.loads(m.raw(self.receipt));req['inputs'][name]['sha256']='f'*64
            code,result=self.call('verify-service-receipt',req)
            self.assertEqual(code,12);self.assertEqual(result['state'],'REFUSED')
        code,_=self.call('verify-service-receipt',dict(self.receipt,module_sha256='f'*64));self.assertEqual(code,12)

    def test_wrong_envelope_hash_version_and_fields_refused(self):
        code,_=self.call('verify-service-receipt',self.receipt,request_sha256='f'*64);self.assertEqual(code,12)
        for change in [dict(schema='vfy.verify-service-receipt-request/2'),dict(private_key='FORBIDDEN')]:
            code,_=self.call('verify-service-receipt',dict(self.receipt,**change));self.assertEqual(code,12)

    def test_base64_is_strict(self):
        req=json.loads(m.raw(self.receipt));req['inputs']['trace']['base64']+='\n'
        code,_=self.call('verify-service-receipt',req);self.assertEqual(code,12)

    def test_wire_input_limit_is_enforced_before_parse(self):
        with patch.object(c,'MAX_STDIN',100):
            code,_=self.call('verify-service-receipt',self.receipt)
        self.assertEqual(code,12)

    def test_reconcile_read_exhaustion_is_unknown_within_budget(self):
        req=dict(self.reconcile,limits=dict(self.reconcile['limits'],read_calls=2))
        code,result=self.call('reconcile-service-repair',req)
        self.assertEqual(code,0);self.assertEqual(result['result']['state'],'UNKNOWN')
        self.assertTrue(result['read_incomplete']);self.assertLessEqual(result['read_usage']['read_calls'],2)

    def test_output_bound_refuses_without_large_stdout(self):
        req=dict(self.receipt,limits=dict(self.receipt['limits'],output_bytes=1024))
        code,result=self.call('verify-service-receipt',req)
        self.assertEqual(code,12);self.assertLess(len(m.raw(result)),1024)

    def test_receipt_does_not_follow_recorded_source_or_pool_paths(self):
        with patch.object(c,'_reconcile',side_effect=AssertionError('no reconcile for receipts')):
            code,_=self.call('verify-service-receipt',self.receipt)
        self.assertEqual(code,0)

if __name__=='__main__':unittest.main()

class AdditionalReadCliTests(unittest.TestCase):
    setUp=ReadCliTests.setUp
    call=ReadCliTests.call

    def test_cached_verifier_cannot_replace_selected_source(self):
        from vfy import service_review_receipt
        with patch.object(service_review_receipt,'verify_receipt',return_value={'state':'FORGED_CACHED_RESULT'}):
            code,result=self.call('verify-service-receipt',self.receipt)
        self.assertEqual(code,0)
        self.assertEqual(result['result']['state'],'VERIFIED_HISTORICAL_REVIEW_RECEIPT')

    def test_enumeration_failure_is_incomplete_unknown(self):
        from pathlib import Path
        import os
        a=self.f.f.f;hidden=a.root/'copy/hidden';hidden.mkdir();original=os.scandir
        def scan(path):
            if Path(path)==hidden:raise PermissionError('synthetic')
            return original(path)
        with patch.object(os,'scandir',side_effect=scan):code,result=self.call('reconcile-service-repair',self.reconcile)
        self.assertEqual(code,0);self.assertTrue(result['read_incomplete'])
        self.assertEqual(result['result']['state'],'UNKNOWN')


class RetainedSourceSelectionTests(unittest.TestCase):
    def test_old_and_current_sources_remain_distinct_and_exact(self):
        from vfy import service_adoption
        old_path, old_raw = c._module('service_adoption', c.ADOPTION_SHA256)
        current_digest = m.sha(Path(service_adoption.__file__).read_bytes())
        current_path, current_raw = c._module('service_adoption', current_digest)
        self.assertNotEqual(old_path, current_path)
        self.assertNotEqual(old_raw, current_raw)
        self.assertEqual(m.sha(old_raw), c.ADOPTION_SHA256)
        self.assertEqual(current_path, Path(service_adoption.__file__).resolve())

    def test_changed_retained_bytes_cannot_fall_back_to_current_source(self):
        _, raw = c._module('service_adoption', c.ADOPTION_SHA256)
        with patch.object(m, 'read_file', return_value=raw + b'\n'):
            with self.assertRaises(m.Refused):
                c._module('service_adoption', c.ADOPTION_SHA256)
