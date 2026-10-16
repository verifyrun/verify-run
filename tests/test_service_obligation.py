"""Focused comparator counterexamples; supplied observations are unit fixtures only."""
import copy,unittest
from vfy import service_obligation as o

class ObligationTests(unittest.TestCase):
 def setUp(self):
  manifest={'subject.py':dict(sha256='a'*64,bytes=10,executable=0)}
  self.ob=dict(schema=o.SCHEMA,edition='IMMUTABLE_SINGLE_EDITION',obligation_id='x',task_id='task',goal='goal',finding=dict(origin='AGENT_PROPOSED_NOT_VERIFY_DISCOVERED',author_id='agent',statement='candidate',evidence=[dict(path='subject.py',sha256='a'*64,start_line=1,end_line=1)]),source_manifest=manifest,requirements={'gain':'gain','keep':'keep'},requirement_paths={'gain':['subject.py'],'keep':['subject.py']},case_mapping={'gain':['a'],'keep':['b']},gain_cases=['a'],preservation_cases=['b'],exclusions=['other behavior'],test_manifest={'tests.py':dict(sha256='b'*64,bytes=10,executable=0)},checker_identity={'sha256':'c'*64},analysis_handoff={})
  before=dict(state='OBSERVED_SELECTED_CASES_NON_SUCCESS',checker_identity=self.ob['checker_identity'],report=dict(events=[dict(id='a',outcome='failure'),dict(id='b',outcome='success')]))
  after=copy.deepcopy(before);after['state']='OBSERVED_SELECTED_CASES_SUCCESS';after['report']['events'][0]['outcome']='success'
  selection=dict(source_sha256='d'*64,requirement_cases=self.ob['case_mapping'],requirements_sha256='f'*64)
  self.kw=dict(baseline=before,candidate=after,baseline_preview=dict(source=manifest,examiner=self.ob['test_manifest']),candidate_preview=dict(source={},examiner=self.ob['test_manifest']),baseline_selection=selection,candidate_selection=dict(selection,source_sha256='e'*64),requirements=dict(schema='vfy.service-requirements/1',requirements=self.ob['requirements']),original_manifest=manifest,task_id='task')
 def test_positive_scoped_comparison(self):
  r=o.compare(self.ob,**self.kw);self.assertEqual(r['full_semantic_coverage'],'UNKNOWN');self.assertFalse(r['authority_granted'])
 def test_non_discriminating_baseline_refused(self):
  self.kw['baseline']['report']['events'][0]['outcome']='success'
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_preservation_loss_refused(self):
  self.kw['candidate']['report']['events'][1]['outcome']='failure'
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_unrelated_mapping_refused(self):
  self.kw['candidate_selection']['requirement_cases']={'gain':['b'],'keep':['a']}
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_omitted_preservation_refused(self):
  self.ob['preservation_cases']=[]
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_uncertain_baseline_refused(self):
  self.kw['baseline']['state']='UNKNOWN'
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_altered_tests_refused(self):
  self.kw['candidate_preview']['examiner']={}
  with self.assertRaises(ValueError):o.compare(self.ob,**self.kw)
 def test_claimed_verify_discovery_refused(self):
  self.ob['finding']['origin']='VERIFY_DISCOVERED'
  with self.assertRaises(ValueError):o.validate(self.ob)
if __name__=='__main__':unittest.main()
