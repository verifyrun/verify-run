"""Authenticated declared task succession, not repair causality or action authority.

The host selects every original checker/trust independently. Producers put the
binding in PREVIEW before original admission; this reader never signs history.
"""
from vfy import child_ledger as m, service_tests as st

SCHEMA = 'vfy.service-test-task-binding/1'
FIELD = 'task_successor_binding'
MAX_LINKS = 64
MAX_CHAIN_BYTES = 16 * 1024 * 1024
EVIDENCE = {'preview_bytes', 'start_bytes', 'result_bytes', 'stdout_bytes',
            'stderr_bytes', 'accounting_snapshot_bytes', 'request_sha256'}
STABLE = ('requirements_sha256', 'examiner_sha256', 'environment_sha256',
          'adapter_sha256', 'capture_sha256', 'runner_sha256', 'labels',
          'case_ids', 'requirement_cases')


def binding(task_bytes, revision, predecessor_sha256):
    m.need(type(task_bytes) is bytes and 0 < len(task_bytes) <= 131072, 'INVALID_TASK_BYTES')
    m.need(type(revision) is int and 1 <= revision <= MAX_LINKS, 'INVALID_TASK_REVISION')
    m.need((revision == 1 and predecessor_sha256 is None) or
           (revision > 1 and m.hex64(predecessor_sha256)), 'INVALID_TASK_PREDECESSOR')
    return dict(schema=SCHEMA, task_sha256=m.sha(task_bytes), revision=revision,
                predecessor_observation_sha256=predecessor_sha256,
                authority_granted=False, automatic_retry=False)


def check_chain(links, *, task_bytes, expected_task_sha256, destination_predecessor_sha256):
    """Verify bounded genesis-to-head evidence using host-selected checkers.

Each link is (TestObservationChecker, raw evidence dict). No checker is learned
from uploaded evidence. Missing legacy bindings refuse rather than infer lineage.
An observation digest includes its exact snapshot and selected verifier limits;
therefore the selected archived snapshot/limits must remain byte-consistent.
The destination supplies its independently retained head, never a report hint.
This read verifies equality only; atomic destination insertion is a separate gate.
"""
    binding(task_bytes, 1, None)
    m.need(type(task_bytes) is bytes and m.hex64(expected_task_sha256) and
           m.sha(task_bytes) == expected_task_sha256, 'SELECTED_TASK_MISMATCH')
    m.need(type(links) is list and 0 < len(links) <= MAX_LINKS, 'CHAIN_LIMIT')
    total = len(task_bytes)
    # Bound all bytes before any cryptographic or JSON work.
    for link in links:
        m.need(type(link) is tuple and len(link) == 2, 'INVALID_LINK')
        checker, evidence = link
        m.need(type(checker) is st.TestObservationChecker and type(evidence) is dict
               and set(evidence) == EVIDENCE, 'INVALID_SELECTED_CHECKER_OR_EVIDENCE')
        m.need(m.hex64(evidence['request_sha256']), 'INVALID_REQUEST_HASH')
        for raw in (*checker.selected.values(), *(evidence[k] for k in EVIDENCE if k != 'request_sha256')):
            m.need(type(raw) is bytes, 'INVALID_CHAIN_BYTES')
            total += len(raw)
            m.need(total <= MAX_CHAIN_BYTES, 'CHAIN_BYTE_LIMIT')
    prior = None
    stable = None
    observations = []
    for revision, (checker, evidence) in enumerate(links, 1):
        observed = checker.check(**evidence)
        m.need(observed['state'] in ('OBSERVED_SELECTED_CASES_SUCCESS',
                                    'OBSERVED_SELECTED_CASES_NON_SUCCESS'), 'UNAUTHENTICATED_OR_INCOMPLETE_OBSERVATION')
        preview = m.load.load_json_bytes(evidence['preview_bytes'])
        m.need(FIELD in preview, 'LEGACY_TASK_SUCCESSION_UNESTABLISHED')
        expected = binding(task_bytes, revision, prior)
        m.need(type(preview[FIELD]) is dict and m.raw(preview[FIELD]) == m.raw(expected),
               'TASK_OR_PREDECESSOR_MISMATCH')
        selected = {k: checker.selection[k] for k in STABLE}
        if stable is None:
            stable = m.raw(selected)
        m.need(m.raw(selected) == stable, 'CHANGED_CRITERIA_OR_EXAMINER')
        prior = m.digest(observed)
        observations.append(dict(revision=revision, observation_sha256=prior,
                                 request_sha256=evidence['request_sha256'], state=observed['state'],
                                 source_sha256=checker.selection['source_sha256']))
    expected_parent = observations[-2]['observation_sha256'] if len(observations) > 1 else None
    m.need(destination_predecessor_sha256 == expected_parent and
           (destination_predecessor_sha256 is None or m.hex64(destination_predecessor_sha256)),
           'DESTINATION_PREDECESSOR_MISMATCH')
    result = dict(destination_predecessor_sha256=destination_predecessor_sha256, schema='vfy.service-test-task-succession/1',
                  state='AUTHENTICATED_DECLARED_TASK_SEQUENCE', task_sha256=expected_task_sha256,
                  stable_selection_sha256=m.sha(stable), observations=observations,
                  input_bytes=total, semantic_adequacy='UNESTABLISHED', repair_causality='UNESTABLISHED',
                  current_source='UNKNOWN', authority_granted=False, automatic_retry=False)
    result['result_sha256'] = m.digest(result)
    return result
