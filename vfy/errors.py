"""Typed failures.

Every failure carries a code from the ERROR class in spec/reason-codes.md. ERROR means the
request was malformed and evaluation never validly began. It is not HOLD and it is not a
decision, and nothing in this module may be used to express either.
"""


class VerifyError(Exception):
    """Base for every typed failure."""

    outcome = "ERROR"
    code = None


class CanonicalFormInvalid(VerifyError):
    """The value cannot be put into canonical form."""

    code = "canonical_form_invalid"


class FloatNotPermitted(VerifyError):
    """A float appeared in a rulebook, candidate, or evidence value."""

    code = "float_not_permitted"


class SurrogateNotPermitted(VerifyError):
    """A string carried a code point in U+D800-U+DFFF, so it has no UTF-8 representation."""

    code = "surrogate_not_permitted"


class SourceEncodingInvalid(VerifyError):
    """Source bytes are not UTF-8, or carry a byte-order mark."""

    code = "source_encoding_invalid"


class SourceSyntaxInvalid(VerifyError):
    """Source is not well-formed in its format."""

    code = "source_syntax_invalid"


class SourceTooDeep(VerifyError):
    """Source nests deeper than the loader's declared maximum depth."""

    code = "source_too_deep"


class SourceConstructUnsupported(VerifyError):
    """Source uses a construct outside the frozen subset of its format."""

    code = "source_construct_unsupported"


class ExpressionParseError(VerifyError):
    """A `when` expression does not parse.

    Carries the location of the failure. The message is fixed per failure kind.
    """

    code = "expression_parse_error"

    def __init__(self, message, offset, line, column, token, expected):
        super().__init__(message)
        self.offset = offset
        self.line = line
        self.column = column
        self.token = token
        self.expected = expected


class ExpressionTypeError(VerifyError):
    """A static type mismatch, provable from the expression text alone."""

    code = "expression_type_error"

    def __init__(self, message, offset=None, line=None, column=None, token=None):
        super().__init__(message)
        self.offset = offset
        self.line = line
        self.column = column
        self.token = token


class RulebookSemanticInvalid(VerifyError):
    """A schema-valid rulebook violates a load-time invariant."""

    code = "rulebook_semantic_invalid"


class UndeclaredEvidenceId(VerifyError):
    """A rulebook names an evidence id it does not declare."""

    code = "undeclared_evidence_id"


class RulebookVersionCollision(VerifyError):
    """Two rulebooks share an identity but differ in content."""

    code = "rulebook_version_collision"


class SnapshotItemInvalid(VerifyError):
    """A snapshot item's status and value combination is incoherent."""

    code = "snapshot_item_invalid"


class SnapshotItemUndeclared(VerifyError):
    """A snapshot carries evidence the rulebook does not declare."""

    code = "snapshot_item_undeclared"


class SnapshotItemMissing(VerifyError):
    """A required evidence declaration has no snapshot item."""

    code = "snapshot_item_missing"


class SnapshotRulebookMismatch(VerifyError):
    """A snapshot names a rulebook other than the pinned one."""

    code = "snapshot_rulebook_mismatch"


class SnapshotDigestMismatch(VerifyError):
    """A snapshot's embedded digest does not match its own payload."""

    code = "snapshot_digest_mismatch"


class EvidenceOrderInvalid(VerifyError):
    """Evidence was acquired after the freeze, or item order is not 0..n-1."""

    code = "evidence_order_invalid"


class RulebookNotAdopted(VerifyError):
    """The rulebook was not adopted when this run started."""

    code = "rulebook_not_adopted"


class AuthorizationOutcomeIneligible(VerifyError):
    """Only ALLOW confers action authority."""

    code = "authorization_outcome_ineligible"


class AuthorizationBindingMismatch(VerifyError):
    """An authorization is bound to objects other than the ones supplied."""

    code = "authorization_binding_mismatch"


class AuthorizationNotYetValid(VerifyError):
    """The authorization is not yet valid at the verification instant."""

    code = "authorization_not_yet_valid"


class AuthorizationExpired(VerifyError):
    """The authorization has expired; expiry is exclusive."""

    code = "authorization_expired"


class AuthorizationNonceReused(VerifyError):
    """The authorization's nonce has already been consumed."""

    code = "authorization_nonce_reused"


class SignatureMalformed(VerifyError):
    """A signature value is not decodable in its declared encoding."""

    code = "signature_malformed"


class SignatureInvalid(VerifyError):
    """A signature does not verify over the artifact's canonical payload."""

    code = "signature_invalid"


class SigningKeyUnknown(VerifyError):
    """No key in the registry matches this key id and version."""

    code = "signing_key_unknown"


class SigningKeyRetired(VerifyError):
    """The signing key is retired."""

    code = "signing_key_retired"


class SigningKeyInvalid(VerifyError):
    """Key material is not a well-formed Ed25519 key."""

    code = "signing_key_invalid"


class ReceiptOutcomeIneligible(VerifyError):
    """ERROR is not a decision and emits no receipt."""

    code = "receipt_outcome_ineligible"


class ReceiptBindingMismatch(VerifyError):
    """A receipt is bound to objects other than the ones supplied."""

    code = "receipt_binding_mismatch"


class ReplayBodyMissing(VerifyError):
    """Replay needs a body that was not supplied."""

    code = "replay_body_missing"


class ReplayBodyMismatch(VerifyError):
    """A supplied body does not match the digest the receipt records."""

    code = "replay_body_mismatch"


class ReplayResultMismatch(VerifyError):
    """The recomputed decision differs from the recorded one."""

    code = "replay_result_mismatch"


class StorePathInvalid(VerifyError):
    """A store path or identifier is unusable."""

    code = "store_path_invalid"


class StoreRecordMissing(VerifyError):
    """No committed record exists for that receipt id."""

    code = "store_record_missing"


class StoreRecordIncomplete(VerifyError):
    """A record is missing a required file."""

    code = "store_record_incomplete"


class StoreRecordConflict(VerifyError):
    """One receipt id cannot mean two contents."""

    code = "store_record_conflict"


class StoreArtifactNoncanonical(VerifyError):
    """Stored bytes are not canonical."""

    code = "store_artifact_noncanonical"


class StoreIndexInvalid(VerifyError):
    """The index is malformed; records govern."""

    code = "store_index_invalid"


class StoreCommitConflict(VerifyError):
    """A staging path or commit target already exists."""

    code = "store_commit_conflict"


class StoreConsumptionConflict(VerifyError):
    """A consumption record conflicts."""

    code = "store_consumption_conflict"


class ExecutionCandidateUnsupported(VerifyError):
    """The candidate does not name a process this runtime can execute."""

    code = "execution_candidate_unsupported"


class ExecutionConfigurationInvalid(VerifyError):
    """The process configuration is unusable, so no launch is attempted."""

    code = "execution_configuration_invalid"


class ExecutionRecordingFailed(VerifyError):
    """The attempt finished and could not be recorded. The authorization is already spent.

    Carries the `stage` that failed and the `receipt` if one was issued, so a caller can persist
    the record later without re-executing anything, and `preserved_at` — the path where the
    signed receipt was kept when the store could still be written to. `preserved_at` is None when
    preservation itself failed, which is a materially different report and is never guessed.

    It also carries `execution`: what was already observed about the child. Every stage below the
    launch line runs *after* the action may have changed the world, so a failure there is allowed
    to leave the record uncertain and is never allowed to leave the execution unknown. The
    completion-clock stage used to discard the launch outcome entirely — the child had exited
    with a status nobody could any longer be told about, which is the same defect shape as losing
    the signed receipt one stage later.
    """

    code = "execution_recording_failed"

    def __init__(self, message, stage, receipt=None, preserved_at=None, execution=None):
        super().__init__(message)
        self.stage = stage
        self.receipt = receipt
        # What the runtime already observed about the child, when it had already observed it.
        # A failure below the launch line may make the *record* uncertain; it may not make the
        # execution unknown. `None` means the child had genuinely not run yet, and is never used
        # to mean "it ran and we lost the details".
        self.execution = execution
        self.preserved_at = preserved_at


class EvidenceAdapterConfigInvalid(VerifyError):
    """An evidence declaration or adapter runtime bound is malformed."""

    code = "evidence_adapter_config_invalid"


class EvidencePathInvalid(VerifyError):
    """An evidence path escapes its root, is a symlink, or is not a regular file."""

    code = "evidence_path_invalid"


class CliWorkspaceInvalid(VerifyError):
    """There is no usable workspace at the given path."""

    code = "cli_workspace_invalid"


class CliWorkspaceConflict(VerifyError):
    """Initialization would overwrite a workspace file whose bytes differ."""

    code = "cli_workspace_conflict"


class CliConfigInvalid(VerifyError):
    """The workspace configuration or trust file is not usable as written."""

    code = "cli_config_invalid"


class CliExecutableNotFound(VerifyError):
    """argv[0] resolves to no executable along the configured search path."""

    code = "cli_executable_not_found"


class CliPathOutsideWorkspace(VerifyError):
    """A supplied path is not inside this workspace's store."""

    code = "cli_path_outside_workspace"


class SchemaRegistryInvalid(VerifyError):
    """A schema document is itself invalid, so no instance can be judged against it."""

    code = "schema_registry_invalid"


class SchemaInvalid(VerifyError):
    """A document failed its schema.

    Carries the machine-readable location of the failure. The message is a fixed string per
    keyword and never contains instance data.
    """

    code = None

    def __init__(self, message, instance_path, schema_path, keyword):
        super().__init__(message)
        self.instance_path = instance_path
        self.schema_path = schema_path
        self.keyword = keyword


class CandidateSchemaInvalid(SchemaInvalid):
    code = "candidate_schema_invalid"


class RulebookSchemaInvalid(SchemaInvalid):
    code = "rulebook_schema_invalid"


class SnapshotSchemaInvalid(SchemaInvalid):
    code = "snapshot_schema_invalid"


class OutcomeSchemaInvalid(SchemaInvalid):
    code = "outcome_schema_invalid"


class AuthorizationSchemaInvalid(SchemaInvalid):
    code = "authorization_schema_invalid"


class ReceiptSchemaInvalid(SchemaInvalid):
    code = "receipt_schema_invalid"
