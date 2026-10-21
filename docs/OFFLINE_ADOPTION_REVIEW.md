# Verify retained adoption evidence without Platform

A recipient can verify the original receipt chain without Platform access, a
producer database, a live source tree, signing keys or another execution. The
result answers **whether these selected historical bytes form the authenticated
chain**. It does not authorize an action, establish current source correctness or
prove that the declared checks were sufficient.

## Trust comes before the upload

Obtain the installed Run artifact/version and its digest through your trusted
release channel. Select these independently of the uploader:

- `owner_trust` and `owner_issuer`: the receipt producer and public verification key;
- `profile_sha256`: the exact authorized historical profile;
- `runtime_id`: the historical runtime selected for authorization verification;
- `action_key`: public authorization key ID, version and status;
- expected final-plan digest: the reviewed subject you intend to examine.

Record those five policy fields as a JSON object in a recipient-controlled file.
Record its exact file SHA256 separately. A policy supplied beside an untrusted
receipt is not independently trusted just because both hashes match. No private
key is needed. Key provenance, revocation policy and acceptable historical scope
are recipient decisions; this example cannot establish them.

The bundle is exactly one JSON object with `plan`, `preparation`, `intent`,
`completion`. Each value contains `base64` of the original bytes and their `sha256`.
Do not reserialize the original receipt inputs. Do not include an uploader policy.
Export the four original inputs from the accepted receipt, not reconstructed data.

## Run the read-only example

Use the explicitly selected installed interpreter; `-I` prevents accidental imports
from the current checkout. Substitute your own reviewed paths and pinned digests:

```sh
/path/to/selected-env/bin/python -I /path/to/source/tools/verify_adoption_offline.py \
  --bundle /path/to/four-inputs.json \
  --policy /path/to/recipient-policy.json \
  --policy-sha256 POLICY_FILE_SHA256 \
  --expected-final-plan-sha256 REVIEWED_FINAL_PLAN_SHA256
```

Exit 0 and `HISTORICAL_ADOPTION_VERIFIED` mean scoped historical verification.
Exit 12/`REFUSED`, malformed output or process failure is not acceptance. All four
flags stay false: authority_granted, current_reliance, automatic_retry,
service_execution. The utility reads bounded input files and calls the existing
verifier; it never calls adoption, source acquisition or a provider. No Platform
service or private fixture is required by the consumer.

Historical task/runtime/rulebook/snapshot/gate identities describe the saved
subject. They do not bind a Platform tenant, prove current authorization or grant
compatibility with a changed checker. New checker trust must be explicitly
examined; unchanged content is not automatic permission to migrate a receipt.
Physical total accounting and semantic acceptance remain UNKNOWN/UNESTABLISHED.

## Scope and conformance

The example preserves the existing `vfy.verify-service-adoption-history-request/1`
contract. Its refusal controls cover wrong policy digest, an uploaded policy, and
input limits. Existing history-verifier controls cover signed chain and gate
mismatch. This is not an extension or new PASS for frozen decision-replay-v1, whose
30 vectors describe a different, narrower contract. Cross-connector atomic order,
checker migration and complete accounting remain separate full-product exits.

The development tree and this example are not a published package. Consult
RELEASE_READINESS_20261020.md before release; old snapshot provenance is historical.
