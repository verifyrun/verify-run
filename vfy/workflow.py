"""Workspace orchestration, per spec/cli.md.

Calls the closed runtime in the order the closed specifications already fix. It evaluates
nothing, verifies nothing, consumes nothing, and replays nothing on its own — every one of those
has an owner, and a second implementation here is how a product starts disagreeing with itself.

This layer and `vfy/cli.py` are the only two that may hold a clock or draw randomness.
"""

import hashlib
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vfy import authorization as auth_module
from vfy import canon, evidence, gate, load, receipt as receipt_module, rulebook, runner, schema
from vfy import snapshot as snapshot_module
from vfy import store as store_module
from vfy.errors import (
    CliConfigInvalid,
    CliExecutableNotFound,
    CliPathOutsideWorkspace,
    CliWorkspaceConflict,
    CliWorkspaceInvalid,
    VerifyError,
)

WORKFLOW_VERSION = 1
CONFIG_VERSION = 1
TRUST_VERSION = 1

VFY_DIR = ".vfy"
CONFIG_NAME = "config.json"
RULEBOOK_NAME = "rulebook.yaml"
TEMPLATES = ("agent-guard", "pipeline-gate", "claims-gate")

_RUNTIME_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX_KEY = re.compile(r"\A[a-f0-9]{64}\Z")
_INSTANT = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class Clock:
    """The one clock in the product. Nothing below this layer may hold one."""

    def now_utc(self):
        # Integer seconds from a UTC-only conversion, formatted without strftime so no locale
        # can reach the string. No fraction, no offset, no floating-point arithmetic.
        parts = time.gmtime(time.time_ns() // 1_000_000_000)
        return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (
            parts.tm_year, parts.tm_mon, parts.tm_mday,
            parts.tm_hour, parts.tm_min, parts.tm_sec)


class FixedClock:
    """For tests and for any caller that wants to state the instant itself."""

    def __init__(self, instant):
        if not _INSTANT.fullmatch(instant):
            raise CliConfigInvalid("An instant must be YYYY-MM-DDTHH:MM:SSZ.")
        self.instant = instant

    def now_utc(self):
        return self.instant


class Identifiers:
    """The two values that must not be derived, and the keys `init` generates."""

    def nonce(self):
        return "n-" + secrets.token_hex(16)

    def receipt_id(self):
        return "r-" + secrets.token_hex(12)

    def signing_seed(self):
        return Ed25519PrivateKey.generate().private_bytes_raw()


class FixedIdentifiers:
    """A deterministic source, so a whole run is reproducible byte for byte."""

    def __init__(self, nonces, receipt_ids, seeds=()):
        self._nonces, self._receipt_ids, self._seeds = list(nonces), list(receipt_ids), list(seeds)

    def nonce(self):
        return self._nonces.pop(0)

    def receipt_id(self):
        return self._receipt_ids.pop(0)

    def signing_seed(self):
        return self._seeds.pop(0)


@dataclass(frozen=True)
class Decision:
    """One rendered outcome. Everything a caller needs and nothing operational."""

    outcome: str
    matched_rule: str | None
    reasons: tuple
    summary: str
    receipt_id: str | None = None
    receipt_path: str | None = None
    executed: bool = False
    exit_status: int | None = None
    notes: tuple = field(default_factory=tuple)


# --- workspace ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class Workspace:
    root: Path
    config: dict
    registry: dict

    @property
    def vfy(self):
        return self.root / VFY_DIR

    def path(self, relative):
        return self.root / relative

    def store(self):
        return store_module.LocalStore(self.vfy)


def schema_registry(spec_dir):
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(Path(spec_dir).glob("*.schema.json"))])


def open_workspace(root, spec_dir):
    """Load and validate one initialized workspace. Nothing ambient is consulted."""
    root = _real_directory(root, "workspace")
    config_path = root / VFY_DIR / CONFIG_NAME
    if not config_path.is_file() or config_path.is_symlink():
        raise CliWorkspaceInvalid(
            "No initialized workspace here; run `vfy init` first: " + str(root))
    config = _check_config(_load_strict(config_path))
    return Workspace(root=root, config=config, registry=schema_registry(spec_dir))


def initialize(root, template, spec_dir, template_dir, identifiers):
    """Create one workspace. Idempotent on identical bytes; never a silent overwrite."""
    if template not in TEMPLATES:
        raise CliConfigInvalid(
            "Unknown template %r; the templates are %s" % (template, ", ".join(TEMPLATES)))
    root = _real_directory(root, "workspace")
    vfy = root / VFY_DIR
    keys = vfy / "keys"
    if vfy.exists() and (vfy.is_symlink() or not vfy.is_dir()):
        raise CliWorkspaceInvalid(".vfy exists and is not a real directory.")

    source = Path(template_dir) / (template + ".yaml")
    _write_or_match(root / RULEBOOK_NAME, source.read_bytes())

    keys.mkdir(parents=True, exist_ok=True)
    authorization_public = _keypair(keys / "authorization.key", identifiers)
    receipt_public = _keypair(keys / "receipt.key", identifiers)

    runtime_id = "local-" + authorization_public.hex()[:16]
    trust = {"trust_version": TRUST_VERSION,
             "authorization": [_trust_entry("authorization-key", authorization_public)],
             "receipt": [_trust_entry("receipt-key", receipt_public)]}
    _write_or_match(keys / "trust.json", canon.canonical_bytes(trust))

    config = {
        "config_version": CONFIG_VERSION,
        "runtime_id": runtime_id,
        "rulebook": RULEBOOK_NAME,
        "template": template,
        "evidence": {"file_root": ".", "command_working_directory": ".",
                     "command_timeout_seconds": 30},
        "keys": {"authorization": ".vfy/keys/authorization.key",
                 "receipt": ".vfy/keys/receipt.key", "trust": ".vfy/keys/trust.json"},
        "execution": {"working_directory": ".", "timeout_seconds": 300, "environment": {}},
        "search_path": ["bin"],
    }
    _write_or_match(vfy / CONFIG_NAME, canon.canonical_bytes(config))

    store_module.LocalStore(vfy)                    # the store creates its own layout
    workspace = open_workspace(root, spec_dir)
    pin_rulebook(workspace)                         # an unusable workspace is not initialized
    return workspace


def _keypair(path, identifiers):
    """Return the public half, generating and writing the seed only if none exists."""
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise CliWorkspaceInvalid("A key path is not a regular file: " + str(path))
        seed = path.read_bytes()
    else:
        seed = identifiers.signing_seed()
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(seed)
    return _public_of(seed, path)


def _public_of(seed, path):
    try:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    except Exception:
        # The seed itself never reaches the message.
        raise CliConfigInvalid("Not a usable Ed25519 signing key: " + str(path)) from None


def _trust_entry(key_id, public_key):
    return {"key_id": key_id, "key_version": 1, "public_key_hex": public_key.hex(),
            "status": "active"}


def _write_or_match(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise CliWorkspaceInvalid("Not a regular file: " + str(path))
        if path.read_bytes() != payload:
            raise CliWorkspaceConflict(
                "This file differs from what init would write, and is not overwritten: "
                + str(path))
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)


def _real_directory(root, what):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise CliWorkspaceInvalid("The %s must be an existing real directory: %s" % (what, root))
    return root


def _load_strict(path):
    try:
        return load.load_json_bytes(path.read_bytes())
    except VerifyError as failure:
        raise CliConfigInvalid("%s is not usable: %s" % (path.name, failure)) from None
    except OSError:
        raise CliConfigInvalid("Could not read " + str(path)) from None


# --- configuration ------------------------------------------------------------------------------

def _check_config(value):
    _exact_keys(value, {"config_version", "runtime_id", "rulebook", "template", "evidence",
                        "keys", "execution", "search_path"}, "config")
    if value["config_version"] != CONFIG_VERSION:
        raise CliConfigInvalid("config_version must be %d." % CONFIG_VERSION)
    if not isinstance(value["runtime_id"], str) or not _RUNTIME_ID.fullmatch(value["runtime_id"]):
        raise CliConfigInvalid("runtime_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}.")
    if value["template"] not in TEMPLATES:
        raise CliConfigInvalid("template must be one of " + ", ".join(TEMPLATES))
    _relative(value["rulebook"], "rulebook")

    ev = value["evidence"]
    _exact_keys(ev, {"file_root", "command_working_directory", "command_timeout_seconds"},
                "evidence")
    _relative(ev["file_root"], "evidence.file_root")
    _relative(ev["command_working_directory"], "evidence.command_working_directory")
    _bounded(ev["command_timeout_seconds"], 1, 300, "evidence.command_timeout_seconds")

    keys = value["keys"]
    _exact_keys(keys, {"authorization", "receipt", "trust"}, "keys")
    for name in ("authorization", "receipt", "trust"):
        _relative(keys[name], "keys." + name)

    execution = value["execution"]
    _exact_keys(execution, {"working_directory", "timeout_seconds", "environment"}, "execution")
    _relative(execution["working_directory"], "execution.working_directory")
    _bounded(execution["timeout_seconds"], 1, 3600, "execution.timeout_seconds")
    if not isinstance(execution["environment"], dict):
        raise CliConfigInvalid("execution.environment must be an object.")
    for name, member in execution["environment"].items():
        if not isinstance(name, str) or not isinstance(member, str):
            raise CliConfigInvalid("execution.environment holds strings only.")

    if not isinstance(value["search_path"], list):
        raise CliConfigInvalid("search_path must be an array.")
    for entry in value["search_path"]:
        _relative(entry, "search_path")
    return value


def _exact_keys(value, expected, where):
    if not isinstance(value, dict):
        raise CliConfigInvalid(where + " must be an object.")
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise CliConfigInvalid("%s carries unknown fields: %s" % (where, ", ".join(unknown)))
    if missing:
        raise CliConfigInvalid("%s is missing: %s" % (where, ", ".join(missing)))


def _bounded(value, low, high, where):
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise CliConfigInvalid("%s must be an integer from %d to %d." % (where, low, high))


def _relative(value, where):
    if not isinstance(value, str) or not value:
        raise CliConfigInvalid(where + " must be a non-empty string.")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CliConfigInvalid(
            where + " must stay inside the workspace, with no traversal: " + value)
    return value


def load_trust(workspace):
    """Return the two verification registries, kept separate on purpose."""
    path = workspace.path(workspace.config["keys"]["trust"])
    value = _load_strict(path)
    _exact_keys(value, {"trust_version", "authorization", "receipt"}, "trust")
    if value["trust_version"] != TRUST_VERSION:
        raise CliConfigInvalid("trust_version must be %d." % TRUST_VERSION)
    registries = {}
    for kind in ("authorization", "receipt"):
        entries = value[kind]
        if not isinstance(entries, list) or not entries:
            raise CliConfigInvalid("trust.%s must be a non-empty array." % kind)
        built = []
        for entry in entries:
            _exact_keys(entry, {"key_id", "key_version", "public_key_hex", "status"},
                        "trust." + kind)
            if not isinstance(entry["public_key_hex"], str) \
                    or not _HEX_KEY.fullmatch(entry["public_key_hex"]):
                raise CliConfigInvalid("A public key is 64 lowercase hex characters.")
            if entry["status"] not in ("active", "retired"):
                raise CliConfigInvalid("A key status is active or retired.")
            built.append({"key_id": entry["key_id"], "key_version": entry["key_version"],
                          "public_key": bytes.fromhex(entry["public_key_hex"]),
                          "status": entry["status"]})
        try:
            registries[kind] = auth_module.build_key_registry(built)
        except VerifyError as failure:
            raise CliConfigInvalid("trust.%s is unusable: %s" % (kind, failure)) from None
    return registries


def load_signing_seed(workspace, which):
    """Read one private seed. Its bytes never reach a message, a log, or an artifact."""
    path = workspace.path(workspace.config["keys"][which])
    if path.is_symlink() or not path.is_file():
        raise CliConfigInvalid("A signing key must be a regular file: " + str(path))
    seed = path.read_bytes()
    _public_of(seed, path)
    return seed, _permissive(path)


def _permissive(path):
    """True when the mode grants group or other access, which the caller warns about."""
    return bool(stat.S_IMODE(path.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO))


# --- the chain ------------------------------------------------------------------------------------

def pin_rulebook(workspace):
    path = workspace.path(workspace.config["rulebook"])
    if path.is_symlink() or not path.is_file():
        raise CliWorkspaceInvalid("The rulebook must be a regular file: " + str(path))
    return rulebook.load_rulebook_bytes(path.read_bytes(), workspace.registry)


def resolve_program(workspace, name):
    """Resolve argv[0] to a path before the candidate is built, digested, or authorized."""
    if os.sep in name or (os.altsep and os.altsep in name):
        candidate = (workspace.path(workspace.config["execution"]["working_directory"]) / name)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return name
        raise CliExecutableNotFound("No executable at " + name)
    # A bare name is searched along the configured path only. Never PATH, never the parent
    # environment: the same rulebook must not mean different programs on different machines.
    for entry in workspace.config["search_path"]:
        candidate = workspace.path(entry) / name
        if candidate.is_file() and not candidate.is_symlink() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise CliExecutableNotFound(
        "%r is not on the workspace search path; write a path or add its directory." % name)


def build_candidate(workspace, argv, frozen_at, identity=None):
    """The exact candidate a command line denotes. Nothing is altered after this."""
    if not argv:
        raise CliExecutableNotFound("No command was given after `--`.")
    resolved = [resolve_program(workspace, argv[0])] + list(argv[1:])
    seed = canon.canonical_bytes({"argv": resolved, "frozen_at": frozen_at})
    candidate = {
        "candidate_id": "c-" + hashlib.sha256(seed).hexdigest()[:32],
        "kind": "command",
        "action": {"summary": " ".join(resolved), "argv": resolved},
    }
    if identity:
        candidate["identity"] = dict(identity)
    return candidate


def acquire(workspace, pinned, instant):
    """Acquire every declared local source. Unsupported ones are named, never faked."""
    acquisitions, unsupported = [], []
    config = workspace.config["evidence"]
    file_root = workspace.path(config["file_root"])
    for declaration in pinned.value()["evidence"]:
        source = declaration["source"]
        if source == "file":
            result = evidence.acquire_file(declaration, file_root, instant)
        elif source == "exec":
            result = evidence.acquire_command(
                declaration, file_root, instant,
                timeout_seconds=config["command_timeout_seconds"],
                working_directory=workspace.path(config["command_working_directory"]))
        else:
            # No adapter, no network, no invention. build_snapshot records it as missing and the
            # rulebook holds on it, which is the honest answer for evidence nobody acquired.
            unsupported.append((declaration["id"], source))
            continue
        acquisitions.append(result.as_acquisition())
    return acquisitions, tuple(unsupported)


def evaluate(workspace, pinned, candidate, instant):
    """Freeze and evaluate. Nothing is authorized, consumed, executed, or written."""
    acquisitions, unsupported = acquire(workspace, pinned, instant)
    snapshot_id = "s-" + hashlib.sha256(
        canon.canonical_bytes({"candidate": candidate["candidate_id"],
                               "frozen_at": instant})).hexdigest()[:32]
    frozen = snapshot_module.build_snapshot(pinned, snapshot_id, instant, acquisitions,
                                            workspace.registry)
    return frozen, gate.evaluate(pinned, candidate, frozen.value(), workspace.registry), unsupported


def run(workspace, argv, clock, identifiers, identity=None):
    """The complete gated run, through the closed chain and nothing else."""
    instant = clock.now_utc()
    pinned = pin_rulebook(workspace)
    candidate = build_candidate(workspace, argv, instant, identity)
    frozen, result, unsupported = evaluate(workspace, pinned, candidate, instant)
    notes = tuple("evidence %s is declared over %s, which this local runtime does not acquire"
                  % (identifier, source) for identifier, source in unsupported)
    outcome = result.outcome
    value = result.value()
    base = dict(outcome=outcome, matched_rule=value.get("matched_rule"),
                reasons=tuple(value["reasons"]), summary=candidate["action"]["summary"],
                notes=notes)

    if outcome == "ERROR":
        # Not a decision, so no receipt: spec/execution-chain.md is explicit.
        return Decision(**base)

    trust = load_trust(workspace)
    receipt_seed, _ = load_signing_seed(workspace, "receipt")
    store = workspace.store()
    receipt_id = identifiers.receipt_id()

    if outcome in ("BLOCK", "HOLD"):
        signed = receipt_module.issue_receipt(
            pinned, candidate, frozen, result, None, None, receipt_id, instant,
            "receipt-key", 1, receipt_seed, workspace.registry)
        store.put_record(signed, pinned, candidate, frozen, None)
        return Decision(receipt_id=receipt_id, receipt_path=_receipt_path(workspace, receipt_id),
                        **base)

    authorization_seed, _ = load_signing_seed(workspace, "authorization")
    nonce = identifiers.nonce()
    granted = auth_module.issue_authorization(
        pinned, candidate, frozen, result, "a-" + receipt_id[2:], nonce,
        workspace.config["runtime_id"], instant, "authorization-key", 1, authorization_seed,
        workspace.registry)

    record = runner.execute_authorized_command(
        pinned, candidate, frozen, result, granted,
        runtime_id=workspace.config["runtime_id"], verification_time=instant,
        acknowledged_at=instant, store=store, authorization_keys=trust["authorization"],
        registry=workspace.registry, receipt_id=receipt_id, receipt_created_at=instant,
        receipt_key_id="receipt-key", receipt_key_version=1, receipt_private_key=receipt_seed,
        cwd=workspace.path(workspace.config["execution"]["working_directory"]),
        environment=workspace.config["execution"]["environment"],
        timeout_seconds=workspace.config["execution"]["timeout_seconds"])

    return Decision(receipt_id=receipt_id, receipt_path=_receipt_path(workspace, receipt_id),
                    executed=record.started, exit_status=record.exit_status, **base)


def check(workspace, candidate_path, clock):
    """Steps 1 to 4, and then stop. Nothing is authorized, consumed, started, or written."""
    instant = clock.now_utc()
    pinned = pin_rulebook(workspace)
    path = Path(candidate_path)
    if path.is_symlink() or not path.is_file():
        raise CliWorkspaceInvalid("The candidate must be a regular file: " + str(path))
    try:
        candidate = load.load_json_bytes(path.read_bytes())
        frozen, result, unsupported = evaluate(workspace, pinned, candidate, instant)
    except VerifyError as failure:
        return Decision(outcome="ERROR", matched_rule=None,
                        reasons=({"code": failure.code, "message": str(failure)},),
                        summary=str(path))
    value = result.value()
    return Decision(outcome=result.outcome, matched_rule=value.get("matched_rule"),
                    reasons=tuple(value["reasons"]),
                    summary=candidate.get("action", {}).get("summary", str(path)),
                    notes=tuple(
                        "evidence %s is declared over %s, which this local runtime does not "
                        "acquire" % (identifier, source) for identifier, source in unsupported))


def replay(workspace, receipt_path):
    """Through LocalStore.get_record, which re-verifies and replays. No shortcut here.

    No clock is read. Replay recomputes a decision from recorded inputs, and every input it needs
    is on disk; a receipt that verified yesterday verifies today.
    """
    store = workspace.store()
    path = Path(receipt_path)
    expected = (workspace.vfy / "receipts").resolve()
    resolved = path.resolve()
    if resolved.parent != expected or resolved.suffix != ".json":
        raise CliPathOutsideWorkspace(
            "A receipt must live in this workspace's store: " + str(path))
    trust = load_trust(workspace)
    return store.get_record(resolved.stem, receipt_keys=trust["receipt"],
                            registry=workspace.registry,
                            authorization_keys=trust["authorization"])


def list_receipts(workspace):
    """The store's own listing, which reconciles against the committed records."""
    return workspace.store().list_receipts()


def _receipt_path(workspace, receipt_id):
    return str(Path(VFY_DIR) / "receipts" / (receipt_id + ".json"))
