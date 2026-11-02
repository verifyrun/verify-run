"""Source-bound named process claims, not semantic sufficiency or action authority.

Independently selected frozen requirements/mapping; read-only service accounting.
Raw structured report is all of stdout, already bound and held by the service pool.
"""
from pathlib import Path

from vfy import child_ledger as m, common_capacity as common, managed_capacity as managed, service_attempt as service
from vfy.errors import VerifyError

PROFILE = 'vfy.service-test-observation/1'
OUTCOMES = {'success','failure','error','skip','expected_failure','unexpected_success'}
FLAGS = {'authority_granted':False,'automatic_retry':False}
SCOPE = {'semantic_acceptance':'UNESTABLISHED','adoption':'UNESTABLISHED',
         'organizational_authority':'UNESTABLISHED'}
FILES = {'selection_bytes':'SELECTION.json','requirements_bytes':'REQUIREMENTS.json',
         'runner_bytes':'runner.bin','preview_bytes':'PREVIEW.json','start_bytes':'START.json',
         'result_bytes':'RESULT.json','stdout_bytes':'stdout.bin','stderr_bytes':'stderr.bin',
         'accounting_snapshot_bytes':'ACCOUNTING.json'}


def identity():
    return {'profile':PROFILE,'source_sha256':m.sha(Path(__file__).read_bytes())}


def name(value):
    return (type(value) is str and 0 < len(value) <= 1024 and value == value.strip()
            and not any(ord(c) < 32 for c in value))


def names(values):
    m.need(type(values) is list and bool(values) and all(name(v) for v in values), 'INVALID_ID_LIST')
    m.need(len(set(values)) == len(values), 'DUPLICATE_SELECTED_ID')


class ReadOnlyServicePool(service.ServicePool):
    """Selected archived bytes only; no signing key, state access or live capability."""
    def snapshot(self):
        return self._selected_snapshot

    def _refuse(self, *args, **kwargs):
        raise m.Refused('READ_ONLY_SELECTED_POOL_NO_MUTATION_OR_EXECUTION')

    admit = consume = settle = mark_unknown = _change = _publish = _refuse

    @classmethod
    def attach(cls, *args, **kwargs):
        raise m.Refused('READ_ONLY_SELECTED_POOL_NO_ATTACH')


def load_service_pool(*, snapshot_bytes, expected_snapshot_sha256, expected_pool_root,
                      expected_config_bytes, owner_trust, child_trust, selected_observer,
                      predecessor_snapshot_bytes, policy_bytes, expected_child_trusts,
                      minimum_revision=0, managed_legacy_snapshot_bytes=None,
                      selected_callback_identity=None, selected_managed_identity=None):
    """Reconstruct selected signed accounting without keys or pool state I/O.

Trust/config/policy/observer are independent caller selections, never learned from
untrusted result/report. Root stays byte-exact even if the old directory is gone.
"""
    for raw in (snapshot_bytes,expected_config_bytes,predecessor_snapshot_bytes,policy_bytes):
        m.need(type(raw) is bytes and len(raw) <= m.MAX_BYTES, 'INVALID_POOL_INPUT')
    m.need(m.hex64(expected_snapshot_sha256) and m.sha(snapshot_bytes) == expected_snapshot_sha256,
           'SELECTED_SNAPSHOT_HASH_MISMATCH')
    root=Path(expected_pool_root)
    m.need(type(expected_pool_root) is str and root.is_absolute() and str(root) == expected_pool_root,
           'INVALID_OR_REWRITTEN_POOL_ROOT')
    old=m.load.load_json_bytes(predecessor_snapshot_bytes)
    schema=old['body']['schema']
    if schema == 'vfy.common-capacity-state/1':
        m.need(managed_legacy_snapshot_bytes is None and selected_callback_identity is None
            and selected_managed_identity is None, 'UNEXPECTED_MANAGED_SELECTION')
        common.verify_capacity_snapshot(predecessor_snapshot_bytes,owner_trust,expected_config_bytes,
            expected_pool_root=expected_pool_root,expected_child_trusts=expected_child_trusts,
            selected_observer=selected_observer)
        owner=object.__new__(common.CapacityOwner)
    else:
        m.need(schema == managed.PROFILE and type(managed_legacy_snapshot_bytes) is bytes
            and len(managed_legacy_snapshot_bytes) <= m.MAX_BYTES, 'UNSUPPORTED_SELECTED_PREDECESSOR')
        managed.verify_managed_snapshot(predecessor_snapshot_bytes,owner_trust,expected_config_bytes,
            expected_pool_root=expected_pool_root,legacy_snapshot_bytes=managed_legacy_snapshot_bytes,
            expected_child_trusts=expected_child_trusts,selected_observer=selected_observer,
            selected_callback_identity=selected_callback_identity,selected_managed_identity=selected_managed_identity)
        owner=object.__new__(managed.ManagedCapacityOwner)
        owner.legacy_bytes=managed_legacy_snapshot_bytes
        owner.legacy_record=m.load.load_json_bytes(managed_legacy_snapshot_bytes)
        owner.legacy_trusts=expected_child_trusts;owner.callback=selected_callback_identity
        owner.legacy_view=common.verify_capacity_snapshot(managed_legacy_snapshot_bytes,owner_trust,expected_config_bytes,
            expected_pool_root=expected_pool_root,expected_child_trusts=expected_child_trusts,selected_observer=selected_observer)
    owner.root=root;owner.trust=owner_trust;owner.config_bytes=expected_config_bytes
    owner.config=m.load.load_json_bytes(expected_config_bytes);owner.issuer=owner.config['owner_issuer']
    m.need(type(child_trust) is dict and bool(child_trust) and all(
        type(v) is dict and set(v) == {'public_key_hex','producer_identity'} and m.hex64(v['public_key_hex'])
        and type(v['producer_identity']) is dict and v['public_key_hex'] != owner_trust[owner.issuer]['public_key_hex']
        for v in child_trust.values()), 'INVALID_INDEPENDENT_CHILD_TRUST')
    owner.observer=selected_observer;owner.child_trust=child_trust
    pool=object.__new__(ReadOnlyServicePool)
    service.ServicePool.__init__(pool,owner,predecessor_snapshot_bytes=predecessor_snapshot_bytes,policy_bytes=policy_bytes)
    view=pool.verify_snapshot(snapshot_bytes)
    m.need(common.integer(minimum_revision) and view['revision'] >= minimum_revision, 'SNAPSHOT_BELOW_SELECTED_REVISION')
    pool._selected_snapshot=snapshot_bytes
    return pool


class TestObservationChecker:
    def __init__(self, pool, *, selection_bytes, requirements_bytes, runner_bytes, limits):
        m.need(type(pool) in (service.ServicePool,ReadOnlyServicePool), 'SELECT_EXISTING_SERVICE_POOL')
        m.need(type(limits) is dict and set(limits) == {'input_bytes','cases','requirements','retained_bytes'}
            and all(common.integer(v) and v > 0 for v in limits.values()), 'INVALID_SELECTED_LIMITS')
        self.pool=pool;self.limits=dict(limits)
        self.selected=dict(selection_bytes=selection_bytes,requirements_bytes=requirements_bytes,runner_bytes=runner_bytes)
        self._bounded(self.selected)
        q=m.load.load_json_bytes(selection_bytes);r=m.load.load_json_bytes(requirements_bytes)
        m.need(type(r) is dict and set(r) == {'schema','requirements'} and
            r['schema'] == 'vfy.service-requirements/1', 'INVALID_FROZEN_REQUIREMENTS')
        req=r['requirements']
        m.need(type(req) is dict and 0 < len(req) <= limits['requirements'] and
            all(name(k) and type(v) is str and bool(v.strip()) for k,v in req.items()), 'INVALID_REQUIREMENTS_OR_LIMIT')
        hashes={'requirements_sha256','source_sha256','examiner_sha256','environment_sha256',
                'adapter_sha256','capture_sha256','runner_sha256'}
        m.need(type(q) is dict and set(q) == {'schema','labels','case_ids','requirement_cases',*hashes,*FLAGS}
            and q['schema'] == 'vfy.service-test-selection/1' and all(q[k] is False for k in FLAGS), 'INVALID_SELECTION')
        m.need(all(m.hex64(q[k]) for k in hashes) and q['requirements_sha256'] == m.sha(requirements_bytes)
            and q['runner_sha256'] == m.sha(runner_bytes), 'SELECTED_BYTES_MISMATCH')
        names(q['labels']);names(q['case_ids'])
        m.need(len(q['case_ids']) <= limits['cases'], 'SELECTED_CASE_LIMIT')
        mapping=q['requirement_cases']
        m.need(type(mapping) is dict and set(mapping) == set(req), 'REQUIREMENT_MAPPING_NOT_EXACT')
        for ids in mapping.values():names(ids)
        m.need(set().union(*(set(ids) for ids in mapping.values())) == set(q['case_ids']), 'CASE_MAPPING_NOT_EXACT')
        self.selection=q;self.requirements=req

    def _bounded(self, inputs):
        m.need(all(type(raw) is bytes and len(raw) <= m.MAX_BYTES for raw in inputs.values()), 'INVALID_OR_OVERSIZED_INPUT')
        count=sum(map(len,inputs.values()))
        m.need(count <= self.limits['input_bytes'], 'INPUT_BYTE_LIMIT')
        return count

    def _base(self):
        return dict(schema=PROFILE,checker_identity=identity(),state='UNKNOWN',
            all_selected_cases_reported_success=False,reason_codes=[],refs={},report=None,requirements={},
            selected_limits=dict(self.limits),costs={'input_bytes':None,'case_events':None,
                'requirements':len(self.requirements),'additional_evidence_charged_to_service_pool':False,
                'checker_cpu_wall_and_global_retention':'UNESTABLISHED'},**SCOPE,**FLAGS)

    def check(self, *, preview_bytes, start_bytes, result_bytes, stdout_bytes, stderr_bytes,
              accounting_snapshot_bytes, request_sha256):
        inputs=dict(self.selected,preview_bytes=preview_bytes,start_bytes=start_bytes,result_bytes=result_bytes,
            stdout_bytes=stdout_bytes,stderr_bytes=stderr_bytes,accounting_snapshot_bytes=accounting_snapshot_bytes)
        out=self._base()
        try:
            out['costs']['input_bytes']=self._bounded(inputs)
            out['refs']={k:m.sha(v) for k,v in inputs.items()}
            m.need(m.hex64(request_sha256), 'INVALID_REQUEST_HASH')
            out['request_sha256']=request_sha256
            report=m.load.load_json_bytes(stdout_bytes)
            m.need(type(report) is dict and set(report) == {'schema','preview_sha256','events','tests_run','completed','successful'}
                and report['schema'] == 'engineer.service-tests/1', 'INVALID_REPORT_SCHEMA')
            m.need(type(report['events']) is list and len(report['events']) <= self.limits['cases'], 'REPORT_CASE_LIMIT')
            m.need(common.integer(report['tests_run']) and type(report['completed']) is bool
                and type(report['successful']) is bool and m.hex64(report['preview_sha256']), 'INVALID_REPORT_TYPES')
            events=report['events']
            m.need(all(type(e) is dict and set(e) == {'id','outcome'} and name(e['id'])
                and type(e['outcome']) is str and e['outcome'] in OUTCOMES for e in events), 'INVALID_REPORT_EVENT')
            out['report']=report;out['costs']['case_events']=len(events)
            p=service.evidence(preview_bytes);r=service.evidence(result_bytes)
            m.need(p.get('schema') == 'engineer.service-observation/1' and
                p.get('test_selection_sha256') == m.sha(self.selected['selection_bytes']) and
                p.get('test_runner_sha256') == self.selection['runner_sha256'], 'PREVIEW_SELECTION_MISMATCH')
            for field in ('source','examiner','environment'):
                m.need(type(p.get(field)) is dict and m.digest(p[field]) == self.selection[field+'_sha256'], 'SELECTED_'+field.upper()+'_MISMATCH')
            for field in ('adapter_sha256','capture_sha256'):
                m.need(p.get(field) == self.selection[field] and p.get(field) == self.pool.policy[field], 'SELECTED_CODE_MISMATCH')
            m.need(p.get('labels') == self.selection['labels'], 'SELECTED_LABELS_MISMATCH')
            ph=m.sha(preview_bytes)
            m.need(service.evidence(start_bytes) == {'preview':ph} and report['preview_sha256'] == ph
                and r.get('preview') == ph, 'RAW_PREVIEW_START_REPORT_MISMATCH')
            m.need(r.get('stdout_sha256') == m.sha(stdout_bytes) and r.get('stderr_sha256') == m.sha(stderr_bytes), 'RAW_STREAM_MISMATCH')
            self.pool.verify_snapshot(accounting_snapshot_bytes)
            b=m.load.load_json_bytes(accounting_snapshot_bytes)['body']
            entries=[e for e in b['entries'] if e['request_sha256'] == request_sha256]
            m.need(len(entries) == 1, 'REQUEST_NOT_IN_SELECTED_ACCOUNTING')
            e=entries[0];q=m.load.load_json_bytes(bytes.fromhex(e['request_raw_hex']))
            m.need(q['preview_sha256'] == ph and q['attempt_root'] == p.get('root') and q['resources'] == p.get('limits')
                and e['start_sha256'] == m.sha(start_bytes), 'ACCOUNTING_START_REQUEST_MISMATCH')
            a=e['result']
            m.need(type(a) is dict and a['result_sha256'] == m.sha(result_bytes) and
                a['stdout_sha256'] == m.sha(stdout_bytes) and a['stderr_sha256'] == m.sha(stderr_bytes)
                and a['stdout_bytes'] == len(stdout_bytes) and a['stderr_bytes'] == len(stderr_bytes), 'ACCOUNTING_RESULT_MISMATCH')
            m.need(e['state'] in ('OBSERVED_EXIT_ZERO','OBSERVED_EXIT_NONZERO') and e['unknown'] is None,
                'ACCOUNTING_UNCERTAIN')
            m.need(r.get('state') == 'PROCESS_OBSERVED' and type(r.get('exit')) is int
                and r['exit'] >= 0 and r.get('limit_failure','MISSING') is None
                and a['exit'] == r['exit'], 'PROCESS_UNCERTAIN')
            m.need(r.get('inputs_unchanged') is True and r.get('post_execution') ==
                {'source':p['source'],'examiner':p['examiner']}, 'POST_EXECUTION_SOURCE_UNCERTAIN')
            ids=[v['id'] for v in events]
            m.need(len(set(ids)) == len(ids), 'DUPLICATE_REPORTED_CASE')
            m.need(set(ids) == set(self.selection['case_ids']), 'REPORTED_CASES_NOT_EXACT')
            m.need(report['tests_run'] == len(events), 'REPORTED_COUNT_MISMATCH')
            m.need(report['completed'] is True, 'REPORT_INCOMPLETE')
            expected_summary=all(e['outcome'] in {'success','skip','expected_failure'} for e in events)
            m.need(report['successful'] is expected_summary, 'REPORT_SUMMARY_INCONSISTENT')
            m.need((r['exit'] == 0) == report['successful'], 'PROCESS_REPORT_INCONSISTENT')
            all_success=all(e['outcome'] == 'success' for e in events)
            by_id={e['id']:e['outcome'] for e in events}
            out['requirements']={rid:{'case_ids':ids,'state':
                'ALL_MAPPED_CASES_REPORTED_SUCCESS' if all(by_id[i]=='success' for i in ids)
                else 'MAPPED_CASES_NOT_ALL_SUCCESS'} for rid,ids in self.selection['requirement_cases'].items()}
            out['state']='OBSERVED_SELECTED_CASES_SUCCESS' if all_success else 'OBSERVED_SELECTED_CASES_NON_SUCCESS'
            out['all_selected_cases_reported_success']=all_success
            out['reason_codes']=[] if all_success else ['SELECTED_CASE_NOT_SUCCESS']
        except (ValueError,TypeError,KeyError,OverflowError,VerifyError) as exc:
            out['reason_codes']=[str(exc) if isinstance(exc,m.Refused) else 'INVALID_'+type(exc).__name__]
        return out

    def retain(self, destination, *, recorded_at, **evidence):
        """Exclusive evidence export, never pool mutation or effect replay."""
        m.need(m.text(recorded_at),'INVALID_RECORDED_AT')
        m.need(type(self.pool) is service.ServicePool, 'READ_ONLY_POOL_CANNOT_SIGN_NEW_RECEIPT')
        observed=self.check(**evidence)
        inputs=dict(self.selected,**{k:v for k,v in evidence.items() if k != 'request_sha256'})
        self._bounded(inputs)
        files={FILES[k]:v for k,v in inputs.items()}
        files['OBSERVATION.json']=m.raw(observed)
        m.need(all(len(data) <= m.MAX_BYTES for data in files.values()), 'RETAINED_MEMBER_SIZE_LIMIT')
        manifest={k:m.sha(v) for k,v in files.items()}
        body=dict(schema='vfy.service-test-evidence/1',checker_identity=identity(),recorded_at=recorded_at,
            manifest=manifest,observation_sha256=manifest['OBSERVATION.json'],
            selected_limits=self.limits,input_bytes=observed['costs']['input_bytes'],
            retained_bytes=0,additional_evidence_charged_to_service_pool=False,**SCOPE,**FLAGS)
        # Fixed-point includes the signed receipt's own byte length; no hidden manifest overhead.
        for _ in range(8):
            receipt=m.envelope(body,self.pool.owner.key,self.pool.owner.issuer);raw=m.raw(receipt)
            total=sum(map(len,files.values()))+len(raw)
            if body['retained_bytes'] == total:break
            body['retained_bytes']=total
        else:raise m.Refused('RECEIPT_SIZE_UNSTABLE')
        m.need(total <= self.limits['retained_bytes'], 'RETENTION_BYTE_LIMIT')
        dest=Path(destination)
        m.need(dest.is_absolute() and dest == dest.resolve(), 'NONCANONICAL_EVIDENCE_DESTINATION')
        dest.mkdir(mode=0o700);m.sync_dir(dest.parent)
        for filename,data in files.items():m.fresh(dest/filename,data)
        m.fresh(dest/'RECEIPT.json',raw);m.sync_dir(dest)
        return receipt

    def verify_retained(self, directory):
        """Authenticate and recompute retained evidence; no execution or pool writes."""
        root=Path(directory)
        m.need(root.is_absolute() and root == root.resolve(), 'NONCANONICAL_EVIDENCE_DIRECTORY')
        receipt_raw=m.read_file(root/'RECEIPT.json')
        receipt=m.load.load_json_bytes(receipt_raw)
        b=m.authenticate(receipt,self.pool.owner.trust)
        m.need(receipt['issuer_identity'] == self.pool.owner.issuer and set(b) ==
            {'schema','checker_identity','recorded_at','manifest','observation_sha256','selected_limits',
             'input_bytes','retained_bytes','additional_evidence_charged_to_service_pool',*SCOPE,*FLAGS}, 'INVALID_RETAINED_RECEIPT')
        m.need(b['schema'] == 'vfy.service-test-evidence/1' and b['checker_identity'] == identity()
            and b['selected_limits'] == self.limits and all(b[k] == v for k,v in SCOPE.items())
            and all(b[k] is False for k in FLAGS) and b['additional_evidence_charged_to_service_pool'] is False
            and m.text(b['recorded_at']), 'RETAINED_SELECTION_MISMATCH')
        m.need(type(b['manifest']) is dict and set(b['manifest']) == {*FILES.values(),'OBSERVATION.json'}, 'INVALID_MANIFEST')
        files={name:m.read_file(root/name) for name in b['manifest']}
        m.need(all(m.sha(raw) == b['manifest'][name] for name,raw in files.items()), 'RETAINED_BYTES_CHANGED')
        m.need(sum(map(len,files.values()))+len(receipt_raw) == b['retained_bytes'] <= self.limits['retained_bytes'], 'RETAINED_BYTE_COUNT_MISMATCH')
        inputs={key:files[filename] for key,filename in FILES.items()}
        m.need(self._bounded(inputs) == b['input_bytes'] and
            all(inputs[k] == v for k,v in self.selected.items()), 'RETAINED_INPUT_SELECTION_MISMATCH')
        observed=m.load.load_json_bytes(files['OBSERVATION.json'])
        args={k:v for k,v in inputs.items() if k not in self.selected}
        recomputed=self.check(**args,request_sha256=observed.get('request_sha256'))
        m.need(m.raw(recomputed) == files['OBSERVATION.json'] and
            m.sha(files['OBSERVATION.json']) == b['observation_sha256'], 'RETAINED_OBSERVATION_MISMATCH')
        return recomputed
