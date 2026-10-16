"""Public reader controls, using fresh synthetic signed bytes only."""
import base64,io,json,unittest
from unittest.mock import patch
from tests.test_service_tests import ObservationTests
from vfy import child_ledger as m, service_tests_cli as c


def packed(raw):return dict(base64=base64.b64encode(raw).decode(),sha256=m.sha(raw))

class SelectedCaseCliTests(unittest.TestCase):
    def setUp(self):
        self.f=ObservationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.observed();f=self.f.f;old=f.old
        context=m.raw(dict(pool_root=str(old.root),config_hex=old.config_bytes.hex(),
            owner_trust=old.trust,child_trust=old.child_trust,observer=old.observer,
            head_hex=f.head.hex(),policy_hex=f.kw['policy_bytes'].hex()))
        a=self.f.args
        entry=json.loads(a['accounting_snapshot_bytes'])['body']['entries'][0]
        data=dict(context=context,snapshot=a['accounting_snapshot_bytes'],selection=self.f.selection_bytes,
            requirements=self.f.requirements,runner=self.f.runner,request=bytes.fromhex(entry['request_raw_hex']))
        data.update({k:a[k+'_bytes'] for k in ('preview','start','result','stdout','stderr')})
        self.q=dict(schema='vfy.check-service-tests-request/1',module_sha256=c.CHECKER_SHA256,
            minimum_revision=4,inputs={k:packed(v) for k,v in data.items()},
            limits=dict(input_bytes=16777216,output_bytes=1048576,cases=4096,requirements=1024))

    def call(self,q=None,**kwargs):
        raw=m.raw(self.q if q is None else q);out=io.StringIO()
        args=dict(request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out);args.update(kwargs)
        code=c.run(**args);return code,json.loads(out.getvalue())

    def test_exact_historical_result_no_live_reads(self):
        original=m.read_file
        def only_code(path):
            self.assertIn(path.name,('service_tests.py',))
            return original(path)
        with patch.object(m,'read_file',side_effect=only_code):code,r=self.call()
        self.assertEqual(code,0);self.assertEqual(r['result']['state'],'OBSERVED_SELECTED_CASES_SUCCESS')
        self.assertFalse(r['authority_granted']);self.assertFalse(r['current_source_checked'])
        self.assertFalse(r['read_cost_charged'])

    def test_each_input_digest_tamper_refused(self):
        for name in c.NAMES:
            q=json.loads(m.raw(self.q));q['inputs'][name]['sha256']='f'*64
            self.assertEqual(self.call(q)[0],12,name)

    def test_wrong_schema_module_extra_field_revision_and_request(self):
        for change in [dict(schema='wrong'),dict(module_sha256='f'*64),dict(private_key='forbidden'),dict(minimum_revision=999),dict(minimum_revision=True)]:
            self.assertEqual(self.call(dict(self.q,**change))[0],12)
        self.assertEqual(self.call(request_sha256='f'*64)[0],12)

    def test_rebound_stream_unknown(self):
        q=json.loads(m.raw(self.q));q['inputs']['stdout']=packed(b'{}')
        code,r=self.call(q);self.assertEqual(code,0);self.assertEqual(r['result']['state'],'UNKNOWN')

    def test_context_trust_root_and_version_refuse(self):
        for field,value in [('owner_trust',{}),('pool_root','/wrong-selected-root'),('extra','forbidden')]:
            q=json.loads(m.raw(self.q));ctx=json.loads(base64.b64decode(q['inputs']['context']['base64']))
            ctx[field]=value;q['inputs']['context']=packed(m.raw(ctx))
            self.assertEqual(self.call(q)[0],12)

    def test_byte_count_case_output_and_wire_limits(self):
        for field,value in [('input_bytes',1),('cases',1),('output_bytes',1024)]:
            q=json.loads(m.raw(self.q));q['limits'][field]=value
            code,r=self.call(q);self.assertEqual(code,12);self.assertIsNone(r['result'])
        with patch.object(c,'MAX_STDIN',100):self.assertEqual(self.call()[0],12)

    def test_noncanonical_encoding_refuses(self):
        q=json.loads(m.raw(self.q));q['inputs']['stdout']['base64']+='\n'
        self.assertEqual(self.call(q)[0],12)

    def test_cached_verifier_not_used(self):
        from vfy import service_tests
        with patch.object(service_tests.TestObservationChecker,'check',side_effect=AssertionError('cached')):
            self.assertEqual(self.call()[0],0)

if __name__=='__main__':unittest.main()
