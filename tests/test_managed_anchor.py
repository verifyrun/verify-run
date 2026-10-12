"""Focused r2 original state anchor versus exact current same-subject inspection."""
import copy, importlib.util,json
from pathlib import Path
from test_managed_capacity import ManagedTests,action,seal,file_ref,prepare,local_start,consume
from vfy import managed_capacity as mc,child_ledger as m


def revised(a, patch=None):
    q,start,capture,receipt,complete=copy.deepcopy(a)
    original=json.loads(Path(q['basis']['path']).read_bytes())
    original['review_revision']='follow-on-current-inspection'
    if patch:patch(original)
    current=file_ref(Path(q['basis']['path']+'-follow-on'),m.raw(original))
    q['basis']=current;q['source_refs'][0]=current
    p=json.loads(start);p['input_artifacts']=[current];p['attempt_id']='follow-on';start=m.raw(p)
    Path(q['parent_start']['path']).write_bytes(start);q['parent_start']['sha256']=m.sha(start);q['attempt_id']=p['attempt_id']
    c=json.loads(capture);c.pop('identity_sha256');c['refs']['inspection']=current;c['snapshot']['observation']['task']['inspection_sha256']=current['sha256']
    capture=seal(c);q['capture']['sha256']=m.sha(capture);q['capture_identity']=json.loads(capture)['identity_sha256'];Path(q['capture']['path']).write_bytes(capture)
    r=json.loads(receipt);r.pop('identity_sha256');r['capture_id']=q['capture_identity'];receipt=seal(r)
    d=json.loads(complete);d.pop('identity_sha256');d['capture_id']=q['capture_identity'];d['receipt_sha256']=json.loads(receipt)['identity_sha256'];complete=seal(d)
    for prefix,data in [('receipt',receipt),('complete',complete)]:q[prefix+'_sha256']=m.sha(data);q[prefix+'_bytes']=len(data)
    return q,start,capture,receipt,complete


class AnchorTests(ManagedTests):
    # Inherit setup only; direct selected suite below avoids broad historical controls.
    def test_distinct_current_inspection_same_subject_full_write(self):
        a=revised(action(self.base,self.o));self.assertNotEqual(a[0]['basis']['sha256'],a[0]['binding_basis']['sha256'])
        g=prepare(self.o,a);local_start(a);consume(g,a)
        m.fresh(Path(a[0]['destination']),a[3]);m.fresh(Path(a[0]['managed_attempt'])/'COMPLETE.json',a[4])
        g.settle(callback_bytes=a[3],complete_bytes=a[4],recorded_at='TEST')
        self.assertEqual(self.state()['managed_entries'][0]['settlement']['state'],'KNOWN_LOCAL_MANAGED_RECEIPT')
    def test_old_anchor_cannot_be_replaced_by_current(self):
        a=revised(action(self.base,self.o));a[0]['binding_basis']=a[0]['basis']
        with self.assertRaises(m.Refused):prepare(self.o,a)
    def test_changed_current_subject_refused(self):
        a=revised(action(self.base,self.o),lambda v:v['task_source_binding'].update(task_subject_identity_sha256='c'*64))
        with self.assertRaises(m.Refused):prepare(self.o,a)
    def test_changed_current_task_refused(self):
        a=revised(action(self.base,self.o),lambda v:v['task_source_binding'].update(task_id='OTHER'))
        with self.assertRaises(m.Refused):prepare(self.o,a)
    def test_changed_current_repository_refused(self):
        a=revised(action(self.base,self.o),lambda v:v.update(repository='/wrong'))
        with self.assertRaises(m.Refused):prepare(self.o,a)
    def test_old_source_reproduces_follow_on_refusal(self):
        a=revised(action(self.base,self.o));q=dict(a[0]);q.pop('binding_basis')
        oldpath=Path(mc.__file__).resolve().parents[2]/'source/vfy/managed_capacity.py'
        spec=importlib.util.spec_from_file_location('frozen_managed_r1',oldpath);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        view=object.__new__(old.ManagedCapacityOwner);view.__dict__.update(self.o.__dict__)
        with self.assertRaises(m.Refused):view.inspect_managed_request(m.raw(q),*a[1:])
