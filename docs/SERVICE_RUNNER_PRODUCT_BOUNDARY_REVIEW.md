# Exact confined runner / PN-0 independent review

Disposition: ADMISSIBLE_EXACT_CONFINED_TEST_ADAPTER_ONLY. No substantive PN-0 violation
found in the inspected source and existing observer route. No Engineer edit, service execution,
subject import, gate waiver or claim of whole-product closure.

Runner: `engineer/change/service_test_runner.py`
SHA256: `b4e9cd392f852701b734ebf44df958383f47d270b46ae19730a572fb86b43b19`.
Observer: `engineer/change/service_observation.py`
SHA256: `1adb9a7b29368ef52f359599c92f8041c8ae4b7d545bd5c9976d64e609c36ad4`.

## Governing distinction

PRODUCT_NORTH_STAR.md PN-0 prohibits a second customer application (server, browser UI,
login, persistent customer surface); Engineer supplies typed construction objects. The
product gate's law 4 approximates that by scanning all of change/converse/quality/surface
for transport imports, including Django. Current gate has only a narrow urllib.parse
exception, not a general reviewed-Django mechanism. Current law 4 returns exactly three
findings in this runner. Do not remove Django from TRANSPORT or exempt change/ wholesale.

Read the complete runner. Its three Django imports are exactly:

```python
from django.test.runner import DiscoverRunner
from django.conf import settings
from django.utils.module_loading import import_string
```

These select project test configuration and the test-runner base, not HTTP routing,
serving, UI rendering, authentication or application persistence. `import_string` loads
application-controlled project runner code and can have import/setup/teardown effects:
this review does NOT declare these imports intrinsically inert or safe outside confinement.
The recorded source refuses project overrides of run_suite/get_resultclass, preserves
project setup/teardown, and records unittest terminal outcomes including subtest failures
and unexpected setup/teardown holders. Missing/duplicate/extra/skipped cases cannot gain
selected-case success through the independent checker. Report completion means run_suite
returned; exceptions or uncertainty are not semantic success. In-process code can forge
this report. This remains explicitly untrusted evidence.

The inspected production references to the runner are in the observer: read/copy its bytes,
hash them into PREVIEW, revalidate package and copied runner hashes, and name the copied
runner in the separately approved sandbox child. It is not imported by an ordinary UI
transport module. The observer validates exact PREVIEW approval, adapter/capture/runner and
input identities, refuses existing START, writes durable START before launch, and uses
macOS Seatbelt deny-default with no network allowance and bounded output/time/resources.
The accounted path additionally requires the existing live Run consumption boundary.
The legacy explicit local execute path is not thereby made accounted. These are reviewed
source properties, not a new service execution or broader platform/runtime attestation.

## Smallest exact-source gate solution for Root

Add a separate predicate to law 4, alongside (not replacing) `_reviewed_parse_only`:

1. Require exact audited-root relative path `engineer/change/service_test_runner.py`.
2. Require the runner hash above and the observer hash above, read from the supplied
   audited `root`, never the gate checkout. Fail closed on absent/unreadable inputs.
3. Require an absolute ImportFrom (level 0), exactly one unaliased imported name, matching
   one of the three module/name pairs above. No Django package-wide allowance.
4. Exempt only that matching import node. Continue checking every other import/module.

Executable independent predicate prototype and static controls:
`scripts/review_service_runner_product_boundary.py` in the Run private review branch.
This is a review artifact, not an installed Engineer gate modification.

Prototype controls passed: changed runner bytes; changed observer bytes; byte-identical
runner relocated to surface, another change file or assist; `import django`; django.http;
aliased DiscoverRunner; urllib.request; sqlite3; added transport changing the runner hash.
Each refuses the exception. Exact three imports pass only with both selected source hashes.
No Django or subject code was imported to run these controls.

Root must integrate this predicate and test the actual law against planted trees: exact
subject removes only these three findings; byte changes and relocation keep findings;
HTTP/client/persistence additions elsewhere remain findings; altered observer invalidates
runner exception. Preserve existing urllib.parse and transport negative controls. Prototype
results do not claim those integration tests or hosted CI have run.

No production runner source change is needed for this scoped finding. Source edits would
invalidate the runner/PREVIEW selection and require a new review; do not rewrite accepted
history. Governance-oracle timeout and sealed historical portability remain unresolved,
not disproved by this disposition. Semantic/full-cost/Platform/full-V1 closure remains OPEN.
