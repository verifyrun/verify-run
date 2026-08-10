"""Closure Unit 14 — release gates, package contents, and documentation accuracy.

These are the checks that must never again depend on somebody remembering to run a grep.
"""

import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tokenize
import unittest
import zipfile

import yaml

from vfy import __version__, canon, load, resources, rulebook, schema

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"

# The scanners necessarily contain the words they look for, so they exclude themselves. Nothing
# else is exempt.
SCANNER_EXEMPT = {"tests/test_release.py", "tests/test_adapters.py", "tests/test_execution.py",
                  "tests/test_cli.py",
                  # CLAUDE.md *declares* the banned vocabulary and the legacy exclusion. It can no
                  # more be scanned for them than the scanners above can scan themselves.
                  "CLAUDE.md"}

# Directories the scanners do not walk, matched as whole path *segments*. The previous form
# tested `part in relative` against the joined path, so every one of these was a substring trap:
# `.git` swallowed `.github/workflows/*` and `.gitignore`, and `build` swallowed every
# `tools/build_conformance_*.py`. The secret, vocabulary, and legacy gates therefore never read
# the CI workflow or the tools that generate the conformance kit — the files most able to carry a
# credential and least likely to be noticed. A gate that skips what it exists to check is not a
# gate, so this matches segments and the test below proves those exact paths are reached.
SKIP_TREES = (".venv", ".git", "dist", "build", "__pycache__", "verify-run", ".vfy")


def _skipped(relative):
    return any(segment in SKIP_TREES for segment in relative.split("/")[:-1] or [""]) \
        or relative.split("/")[0] in SKIP_TREES


def _repository_files(suffixes=None):
    for path in sorted(REPO_ROOT.rglob("*")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        if not path.is_file() or _skipped(relative):
            continue
        if relative in SCANNER_EXEMPT:
            continue
        if suffixes and path.suffix not in suffixes:
            continue
        yield relative, path


def _text(path):
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


class VocabularyGate(unittest.TestCase):
    """Banned theory and legacy vocabulary, across every public surface."""

    EXACT = ("PAS", "PAS_s", "PAS_h", "TEMPOLOCK", "CHORDLOCK", "GLYPHLOCK", "AURA", "ELF")
    ANYCASE = ("resonance", "coherence", "regime", "corridor", "entitlement", "constitution",
               "forcing", "admissibility", "lockgraph", "glyph", "phase", "kernel")

    def test_no_banned_vocabulary_anywhere_in_the_repository(self):
        exact = re.compile(r"\b(" + "|".join(self.EXACT) + r")\b")
        anycase = re.compile(r"\b(" + "|".join(self.ANYCASE) + r")\b", re.IGNORECASE)
        findings = []
        scanned = 0
        for relative, path in _repository_files():
            text = _text(path)
            if text is None:
                continue
            scanned += 1
            for number, line in enumerate(text.splitlines(), 1):
                for pattern in (exact, anycase):
                    found = pattern.search(line)
                    if found:
                        findings.append("%s:%d %s" % (relative, number, found.group(0)))
        self.assertGreater(scanned, 100, "the scanner read almost nothing; check SKIP_TREES")
        self.assertEqual(findings, [], "banned vocabulary on a public surface")

    def test_the_rendered_cli_help_is_clean(self):
        from vfy import cli

        parser = cli.build_parser()
        text = [parser.format_help()]
        for action in parser._actions:
            if getattr(action, "choices", None) and hasattr(action.choices, "values"):
                text += [sub.format_help() for sub in action.choices.values()]
        rendered = "\n".join(text).lower()
        for word in self.ANYCASE:
            self.assertNotIn(word, rendered)

    def test_the_scanner_is_not_vacuous(self):
        exact = re.compile(r"\b(" + "|".join(self.EXACT) + r")\b")
        self.assertTrue(exact.search("the AURA subsystem"))
        anycase = re.compile(r"\b(" + "|".join(self.ANYCASE) + r")\b", re.IGNORECASE)
        self.assertTrue(anycase.search("Kernel"))
        self.assertIsNone(anycase.search("itself"), "ELF-style substring matching would fire here")


class LegacyGate(unittest.TestCase):
    """No runtime linkage to the legacy tree, in code, packaging, or instructions."""

    NAMES = ("ric-core-2", "ric_core", "ric-core")

    def test_no_source_or_packaging_reference(self):
        findings = []
        for relative, path in _repository_files():
            if relative == "docs/EXTRACTION_GUIDE.md":
                continue  # historical salvage boundaries, no linkage; asserted separately
            text = _text(path)
            if text is None:
                continue
            for name in self.NAMES:
                if name in text:
                    findings.append("%s references %s" % (relative, name))
        self.assertEqual(findings, [])

    def test_the_extraction_guide_creates_no_linkage(self):
        text = _text(REPO_ROOT / "docs" / "EXTRACTION_GUIDE.md")
        for instruction in ("pip install", "npm install", "git clone", "sys.path", "import "):
            self.assertNotIn(instruction, text,
                             "the extraction guide instructs a reader to obtain legacy code")

    def test_no_declared_dependency_outside_the_two(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r"dependencies = \[(.*?)\]", text, re.S).group(1)
        # Count the quoted requirements, not commas: ">=42,<52" carries one of its own.
        requirements = re.findall(r'"([^"]+)"', declared)
        self.assertEqual(len(requirements), 2, "runtime dependencies changed: %r" % requirements)
        self.assertTrue(any(r.startswith("PyYAML") for r in requirements))
        self.assertTrue(any(r.startswith("cryptography") for r in requirements))

    def test_no_subprocess_call_into_anything_legacy(self):
        for relative, path in _repository_files({".py"}):
            text = _text(path)
            for name in self.NAMES:
                self.assertNotIn(name, text, relative)


class SecretGate(unittest.TestCase):
    """No credential may enter the repository, and test seeds must say what they are."""

    PATTERNS = {
        "PEM private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "PyPI token": re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}"),
        "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
        "Stripe secret": re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}"),
        "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "secret assignment": re.compile(
            r"(?i)\b(api[_-]?key|client[_-]?secret|password)\s*[:=]\s*['\"][^'\"]{12,}"),
    }
    PUBLISHED_TEST_SEEDS = (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    )

    def test_no_credential_in_the_repository(self):
        findings = []
        for relative, path in _repository_files():
            if path.name.startswith(".env"):
                findings.append("%s is a dotenv file" % relative)
            text = _text(path)
            if text is None:
                continue
            for label, pattern in self.PATTERNS.items():
                if pattern.search(text):
                    findings.append("%s carries a %s" % (relative, label))
        self.assertEqual(findings, [])

    def test_every_published_seed_is_marked_test_only(self):
        unmarked = []
        for relative, path in _repository_files():
            text = _text(path)
            if text is None or not any(s in text for s in self.PUBLISHED_TEST_SEEDS):
                continue
            if "TEST_ONLY" not in text and "TEST-ONLY" not in text:
                unmarked.append(relative)
        self.assertEqual(unmarked, [], "a published test seed appears without saying it is one")

    def test_no_generated_workspace_key_is_tracked(self):
        for relative, path in _repository_files():
            self.assertFalse(relative.endswith(".key"), relative)
            self.assertNotIn("/.vfy/", "/" + relative, relative)

    def test_the_ignore_file_covers_what_must_never_ship(self):
        text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in (".venv/", "__pycache__/", "dist/", "build/", "*.egg-info/", ".DS_Store",
                        ".vfy/", "*.key", ".env", "verify-run/", "verify-run-kickoff.zip"):
            self.assertIn(pattern, text, pattern)

    def test_the_ignore_file_hides_no_authoritative_source(self):
        text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        for never in ("spec/", "templates/", "fixtures/", "tests/", "vfy/", "*.json", "*.yaml",
                      "*.md"):
            self.assertNotIn("\n" + never, "\n" + text, never)


class VersionAndMetadata(unittest.TestCase):
    def test_one_authoritative_version(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(declared, __version__)
        self.assertRegex(__version__, r"\A\d+\.\d+\.\d+((a|b|rc)\d+|\.dev\d+)?\Z")
        self.assertNotEqual(__version__, "1.0.0", "an alpha may not claim 1.0.0")

    def test_the_cli_reports_the_same_version(self):
        completed = subprocess.run([sys.executable, "-m", "vfy.cli", "--version"],
                                   capture_output=True, cwd=str(REPO_ROOT))
        text = (completed.stdout + completed.stderr).decode("utf-8")
        self.assertIn(__version__, text)

    def test_the_declared_python_range_matches_what_is_claimed(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.11"', pyproject)
        workflow = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml")
                                  .read_text(encoding="utf-8"))
        matrix = workflow["jobs"]["test"]["strategy"]["matrix"]["python"]
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for version in matrix:
            self.assertIn(version, readme, "CI tests %s but the README does not say so" % version)

    def test_the_readme_names_the_current_release_not_a_previous_one(self):
        """The README's own release facts must track `__version__`.

        `0.1.0a3` shipped while the README still said the alpha was `0.1.0a2`, still reported the
        conformance reference result against `0.1.0a2`, and still told a reader the reproduction
        command installed `0.1.0a2`. All three were true when written and silently became false at
        the release. A reader has no way to tell which sentences are historical and which are
        stale, so the ones that describe *now* are asserted here.

        Historical sentences are deliberately not policed: "every 0.1.0a1 receipt still verifies"
        is a claim about the past and must stay written in the past.
        """
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for label, pattern in (
                ("the alpha-status version", r"^Version `%s`\." % re.escape(__version__)),
                ("the current conformance reference result",
                 r"Current reference result: \*\*PASS\*\*, 30/30 fixtures, `verify-run %s`"
                 % re.escape(__version__)),
        ):
            with self.subTest(claim=label):
                self.assertRegex(readme, re.compile(pattern, re.M),
                                 "%s does not name %s" % (label, __version__))

    def test_the_readme_does_not_present_verify_run_as_the_whole_system(self):
        """One section has to exist, because its absence is what outside readers got wrong.

        Independent reviewers read the README and concluded the local CLI was the entire offering,
        then judged it against what a large organization would need to deploy — centralized policy,
        fleet management, durable retention, remote evidence. Those belong outside this runtime by
        design, and a reader who cannot tell that will read a deliberate boundary as a missing
        feature.
        """
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Where verify-run fits", readme)
        for phrase in ("not the whole of VERIFY", "built *around* this runtime"):
            self.assertIn(phrase, readme, "the boundary is not stated: %r" % phrase)

    def test_the_entry_point_and_license_are_declared(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('vfy = "vfy.cli:main"', pyproject)
        self.assertIn('license = "Apache-2.0"', pyproject)
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())
        self.assertIn("Apache License", (REPO_ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertTrue((REPO_ROOT / "NOTICE").is_file())


class RuntimeResources(unittest.TestCase):
    def test_the_runtime_reads_only_schemas_and_templates_from_its_distribution(self):
        self.assertEqual(len(list(resources.schema_dir().glob("*.schema.json"))), 6)
        self.assertEqual(len(list(resources.template_dir().glob("*.yaml"))), 3)

    def test_no_module_reaches_out_of_the_package_except_the_documented_fallback(self):
        for path in sorted((REPO_ROOT / "vfy").rglob("*.py")):
            text = _text(path)
            if path.name == "resources.py":
                continue  # the one documented fallback, proven unused when installed
            self.assertNotIn("parent.parent", text, path.name)

    def test_packaging_maps_the_authoritative_directories_rather_than_copying_them(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"vfy._schemas" = "spec"', pyproject)
        self.assertIn('"vfy._templates" = "templates"', pyproject)
        # One copy in the repository, at the authoritative path.
        self.assertFalse((REPO_ROOT / "vfy" / "_schemas").exists())
        self.assertFalse((REPO_ROOT / "vfy" / "_templates").exists())


class DocumentationAccuracy(unittest.TestCase):
    """Every rulebook example in the docs must parse under the real parser."""

    def _registry(self):
        return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                      for p in sorted(resources.schema_dir()
                                                      .glob("*.schema.json"))])

    def _yaml_blocks(self, path):
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        return re.findall(r"```yaml\n(.*?)```", text, re.S)

    def test_every_documented_rulebook_parses_and_pins(self):
        registry = self._registry()
        checked = 0
        for document in ("README.md", "docs/rulebook-reference.md"):
            for block in self._yaml_blocks(document):
                value = yaml.safe_load(block)
                if not isinstance(value, dict) or "rulebook_id" not in value:
                    continue  # a fragment, exercised by the fragment test below
                with self.subTest(document=document):
                    pinned = rulebook.load_rulebook_bytes(
                        canon.canonicalize(value).encode("utf-8"), registry)
                    self.assertTrue(pinned.digest.startswith("sha256:"))
                    checked += 1
        self.assertGreaterEqual(checked, 2, "no complete rulebook example was checked")

    def test_every_documented_when_expression_parses(self):
        from vfy import expr

        checked = 0
        for document in ("README.md", "docs/rulebook-reference.md", "docs/quickstart.md"):
            text = (REPO_ROOT / document).read_text(encoding="utf-8")
            for source in re.findall(r"when: '([^']+)'", text):
                with self.subTest(document=document, when=source):
                    expr.parse_expression(source)
                    checked += 1
        self.assertGreaterEqual(checked, 4)

    def test_the_documented_exit_codes_match_the_implementation(self):
        from vfy import cli

        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for code, phrase in ((cli.EXIT_BLOCK, "| 10 |"), (cli.EXIT_HOLD, "| 11 |"),
                             (cli.EXIT_ERROR, "| 12 |")):
            self.assertIn(phrase, readme, "exit code %d is not documented" % code)
        quickstart = (REPO_ROOT / "docs" / "quickstart.md").read_text(encoding="utf-8")
        for code in (0, 1, 2, 10, 11, 12, 13, 14):
            self.assertIn("`%d`" % code, quickstart, "exit code %d is not documented" % code)

    def test_the_docs_claim_no_excluded_feature(self):
        for document in ("README.md", "docs/quickstart.md", "docs/security.md",
                         "docs/receipts-and-replay.md", "CHANGELOG.md"):
            text = (REPO_ROOT / document).read_text(encoding="utf-8").lower()
            for overclaim in ("exactly-once execution", "formally verified", "guarantees truth",
                              "solves ai safety", "proves the world changed", "is sandboxed",
                              "cross-platform proven"):
                # Only an *asserted* claim counts. "not independently formally verified" is the
                # disclaimer this project is supposed to carry, and a scanner that flagged it
                # would push the docs toward saying less. A negator anywhere earlier in the same
                # sentence clears the phrase; adjacency is too narrow to catch real wording.
                for found in re.finditer(re.escape(overclaim), text):
                    sentence = text[max(0, found.start() - 120):found.start()]
                    sentence = sentence.rsplit(".", 1)[-1].rsplit("\n\n", 1)[-1]
                    negated = re.search(r"\b(not|never|no|without|nor)\b", sentence)
                    self.assertIsNotNone(
                        negated, "%s asserts %r: ...%s"
                        % (document, overclaim, text[found.start() - 60:found.end()]))

    def test_the_documentation_set_exists(self):
        for name in ("README.md", "CHANGELOG.md", "LICENSE", "NOTICE",
                     "docs/quickstart.md", "docs/rulebook-reference.md",
                     "docs/receipts-and-replay.md", "docs/security.md",
                     "docs/release-checklist.md", "spec/release.md"):
            self.assertTrue((REPO_ROOT / name).is_file(), name)


def declared_version():
    """The version this source tree declares. Read, not inferred from a filename."""
    for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError("pyproject.toml declares no version")


def artifacts_for(suffix):
    """Built artifacts in dist/ **for the version this tree declares**, and the rest.

    Selecting `sorted(glob(...))[-1]` is how a package gate ends up certifying source it never
    saw: `dist/` held 0.1.0a2 while the tree declared 0.1.0a3, and three artifact tests passed
    green against the older bytes. An artifact proves something about the source it was built
    from and nothing at all about any other source, so the version has to be part of choosing it.
    """
    if not DIST.is_dir():
        return [], []
    found = sorted(DIST.glob("*" + suffix))
    # Wheel and sdist both spell the version after the first `-`/`_` separated distribution name.
    tag = declared_version()
    matching = [p for p in found if tag in p.name.split(suffix)[0]]
    return matching, [p for p in found if p not in matching]


class StaleArtifactsAreNotEvidence(unittest.TestCase):
    """A built artifact proves something about the source it was built from. Only that source.

    `dist/` held `verify_run-0.1.0a2.*` for the whole of the 0.1.0a3 line, and the package gate
    picked the newest filename it could find and audited it — so "the wheel carries the runtime
    and nothing else" was a true statement about bytes nobody had built from this tree. The gate
    was green and it was not looking at the release.
    """

    def test_dist_holds_no_artifact_from_another_version(self):
        stale = artifacts_for(".whl")[1] + artifacts_for(".tar.gz")[1]
        self.assertEqual(
            [p.name for p in stale], [],
            "dist/ holds artifacts from another version than the declared %s. They are not "
            "evidence for this source and must be removed before a release is proved."
            % declared_version())


class PackageContents(unittest.TestCase):
    """Runs only when dist/ has been built **for this version**. CI builds first, then invokes it.

    Skipping when nothing is built is honest — there is no artifact to describe. Skipping when
    something *wrong* is built is not, so a mismatched artifact fails here rather than being
    quietly stepped over.
    """

    def setUp(self):
        wheels, stale = artifacts_for(".whl")
        if not wheels:
            if stale:
                self.fail("dist/ holds %s but this tree declares %s; a stale artifact is not "
                          "evidence for this source"
                          % (", ".join(p.name for p in stale), declared_version()))
            self.skipTest("no built artifacts for %s in dist/; run `python -m build` first"
                          % declared_version())

    def _wheel(self):
        return artifacts_for(".whl")[0][-1]

    def _sdist(self):
        found = artifacts_for(".tar.gz")[0]
        self.assertTrue(found, "no source distribution for " + declared_version())
        return found[-1]

    def test_the_wheel_carries_the_runtime_and_nothing_else(self):
        with zipfile.ZipFile(self._wheel()) as archive:
            names = archive.namelist()
        self.assertTrue(any(n.endswith("vfy/cli.py") for n in names))
        self.assertEqual(sum(1 for n in names if n.endswith(".schema.json")), 6)
        self.assertEqual(sum(1 for n in names if n.endswith(".yaml")), 3)
        for forbidden in ("tests/", "fixtures/", ".venv", ".vfy/", "verify-run/",
                          "verify-run-kickoff.zip", "__pycache__", ".DS_Store", ".key"):
            self.assertFalse(any(forbidden in n for n in names),
                             "%s appears in the wheel" % forbidden)
        for n in names:
            self.assertFalse(n.endswith(".md") and "/_schemas/" in n,
                             "specification prose shipped in the wheel: " + n)

    def test_the_source_distribution_can_be_audited(self):
        with tarfile.open(self._sdist()) as archive:
            names = archive.getnames()
        for required in ("LICENSE", "NOTICE", "README.md", "CHANGELOG.md", "pyproject.toml"):
            self.assertTrue(any(n.endswith("/" + required) for n in names), required)
        self.assertTrue(any("/tests/" in n for n in names), "tests must be auditable")
        self.assertTrue(any("/fixtures/" in n for n in names), "fixtures must be auditable")
        for forbidden in (".venv", "/.vfy/", "verify-run-kickoff.zip", "__pycache__", ".key",
                          ".DS_Store"):
            self.assertFalse(any(forbidden in n for n in names),
                             "%s appears in the source distribution" % forbidden)

    def test_no_built_artifact_carries_a_credential(self):
        """Both artifacts. The name said "no built artifact" and it read only the wheel.

        The scanners are exempt from themselves here for exactly the reason they are exempt in the
        source tree: a file whose job is to hold the pattern `-----BEGIN PRIVATE KEY` cannot be
        scanned for it. The exemption is by the same declared list, so it cannot quietly widen —
        the wheel ships no tests at all, and the sdist ships precisely the four self-referential
        test modules `SCANNER_EXEMPT` already names.
        """
        seeds = [bytes.fromhex(s) for s in SecretGate.PUBLISHED_TEST_SEEDS]
        # The same credential definition the source gate uses, against the shipped bytes. A bare
        # `-----BEGIN` prefix was stricter than the source gate and flagged
        # `tools/run_conformance.py`, whose leak detector legitimately names that marker. One
        # definition of "a credential", two corpora — not two definitions that can disagree.
        patterns = dict(SecretGate.PATTERNS)

        def exempt(name):
            return any(name.endswith("/" + relative) for relative in SCANNER_EXEMPT)

        def inspect(label, name, blob):
            if exempt(name):
                return
            for seed in seeds:
                self.assertNotIn(seed, blob, label)
            try:
                text = blob.decode("utf-8")
            except UnicodeDecodeError:
                return
            for kind, pattern in patterns.items():
                self.assertIsNone(pattern.search(text), "%s carries a %s" % (label, kind))

        scanned = 0
        with zipfile.ZipFile(self._wheel()) as archive:
            for name in archive.namelist():
                inspect("wheel:" + name, name, archive.read(name))
                scanned += 1
        with tarfile.open(self._sdist()) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is not None:
                    inspect("sdist:" + member.name, member.name, handle.read())
                    scanned += 1
        self.assertGreater(scanned, 200, "the artifact scan read almost nothing")
        # Not vacuous: the same patterns, applied to a planted credential, must fire. A scan that
        # reads 400 files and could not recognise a key is a green light and nothing else.
        planted = "-" * 5 + "BEGIN RSA " + "PRIVATE KEY" + "-" * 5 + "\nMIIB\n"
        for probe in (planted, 'api_key = "' + "z" * 20 + '"', "AKIA" + "A" * 16):
            self.assertTrue(any(p.search(probe) for p in patterns.values()),
                            "the artifact scan would not recognise %r" % probe[:24])

    def test_the_source_distribution_ships_what_its_own_tests_read(self):
        """The sdist's auditability claim, checked against the artifact rather than MANIFEST.in.

        The sdist carried `tests/` but not the `conformance/` kit those tests run, nor the
        `tools/` that drive it, nor `.gitignore` that the secret gate inspects — so 37 of its own
        tests went red for anyone who ran them from the artifact instead of from a git checkout.
        """
        with tarfile.open(self._sdist()) as archive:
            names = archive.getnames()
        required = ("/conformance/decision-replay-v1/profile.json",
                    "/conformance/decision-replay-v1/fixtures/manifest.json",
                    "/conformance/decision-replay-v1/result.schema.json",
                    "/tools/run_conformance.py", "/tools/conformance_adapter.py",
                    "/tools/check_conformance_result.py",
                    "/docs/conformance/decision-replay-v1.md", "/.gitignore")
        for name in required:
            self.assertTrue(any(entry.endswith(name) for entry in names),
                            "the sdist ships a test that reads %s and not the file" % name)
        bundles = len({entry.rsplit("/", 1)[0] for entry in names
                       if "/conformance/decision-replay-v1/fixtures/" in entry
                       and entry.endswith(".json")})
        self.assertGreaterEqual(bundles, 30, "the sdist must carry the whole fixture set")
        # Internal working notes are not part of the verification proposition and must not ship.
        self.assertFalse(any("/docs/audit/" in entry for entry in names),
                         "internal audit notes shipped in the source distribution")


class ScannersReachWhatShips(unittest.TestCase):
    """A gate that skips the files most able to carry a credential is not a gate.

    `SKIP_TREES` was matched with `part in relative` against the joined path, so `.git` swallowed
    `.github/workflows/*` and `.gitignore`, and `build` swallowed every
    `tools/build_conformance_*.py`. The secret, vocabulary, and legacy scanners never read the CI
    workflow — the one file that legitimately handles credentials — or the tools that generate
    the published conformance kit.
    """

    REACHED = (".github/workflows/ci.yml", ".gitignore",
               "tools/build_conformance_manifest.py", "tools/build_conformance_fixtures.py",
               "tools/build_conformance_manifest_of_record.py", "tools/run_conformance.py",
               "tools/conformance_adapter.py")
    EXCLUDED = ("dist/x.whl", ".venv/lib/x.py", ".git/config", "build/lib/x.py",
                "vfy/__pycache__/x.pyc", "verify-run/index.js", ".vfy/store.json")

    def test_the_scanner_corpus_contains_the_files_it_used_to_skip(self):
        corpus = {relative for relative, _ in _repository_files()}
        for name in self.REACHED:
            with self.subTest(path=name):
                self.assertIn(name, corpus, "%s is still invisible to the scanners" % name)

    def test_genuinely_excluded_trees_are_still_excluded(self):
        for name in self.EXCLUDED:
            with self.subTest(path=name):
                self.assertTrue(_skipped(name), "%s should not be scanned" % name)

    def test_a_substring_can_no_longer_be_mistaken_for_a_path_segment(self):
        for name in (".github/workflows/ci.yml", ".gitignore", "tools/build_x.py",
                     "distribution.md", "rebuild.py", "a/buildings/b.py"):
            with self.subTest(path=name):
                self.assertFalse(_skipped(name))

    def test_a_planted_credential_is_caught_in_every_shipped_location(self):
        """Plant the marker the secret gate looks for, in files that were previously skipped."""
        planted = "-" * 5 + "BEGIN RSA " + "PRIVATE KEY" + "-" * 5
        for name in self.REACHED:
            path = REPO_ROOT / name
            if not path.is_file():
                continue
            original = path.read_bytes()
            try:
                path.write_bytes(original + ("\n# " + planted + "\n").encode("utf-8"))
                found = any(planted in (_text(REPO_ROOT / relative) or "")
                            for relative, _ in _repository_files())
                self.assertTrue(found, "a planted credential in %s was not reachable" % name)
            finally:
                path.write_bytes(original)
