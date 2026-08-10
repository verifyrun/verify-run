"""The first five minutes, executed.

Every other suite in this repository proves the engine is trustworthy: determinism, hostile
inputs, signatures, receipts, replay, release integrity. None of them proved the thing a stranger
actually meets first — that you can install the artifact, copy what the README shows, and get a
real gated action with an outcome you can read.

So this suite is the first-use journey itself, run end to end **against the built wheel installed
into a clean environment**, from a directory that is not the checkout. It extracts the commands
from `README.md` rather than restating them, because a quickstart that drifts from the README is
worse than none: the reader copies what is written, not what a test remembers.

It is deliberately not a UX opinion. It asserts three things a stranger needs and nothing about
taste:

  * the documented commands run, in the documented order, and produce the documented outcomes;
  * all three of ALLOW, BLOCK and HOLD are reachable and readable from that same workspace;
  * nothing the stranger reads on the way — README quickstart or command output — uses a word
    from the banned vocabulary.

The last one is the zero-theory claim, checked where it matters. The vocabulary gate already reads
the repository's *files*; it has never read what the program *says to a user*.
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"
README = REPO_ROOT / "README.md"

# Imported, not restated. Two copies of the banned vocabulary would be two vocabularies, and this
# file would have had to join the scanner's self-exemption list to avoid matching its own contents
# — which is how a gate quietly stops covering a file. `test_release` ships in the sdist beside
# this one, so the import holds when the suite runs from the unpacked artifact.
try:                                     # `discover -t .` names the package; direct runs do not
    from tests.test_release import VocabularyGate
except ImportError:
    from test_release import VocabularyGate

BANNED = VocabularyGate.EXACT
BANNED_ANYCASE = VocabularyGate.ANYCASE


def declared_version():
    for line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError("pyproject.toml declares no version")


def quickstart_blocks():
    """The shell blocks of the README's quickstart, in the order a reader meets them.

    Read from the README so the two cannot disagree. A block is included from the quickstart
    heading up to the next top-level heading; transcript blocks (fenced without a language) are
    output being shown, not commands to run, and are skipped.
    """
    text = README.read_text(encoding="utf-8")
    started = re.search(r"^## .*[Qq]uickstart.*$", text, re.M)
    assert started, "README.md has no quickstart section"
    rest = text[started.end():]
    stop = re.search(r"^## ", rest, re.M)
    section = rest[: stop.start()] if stop else rest
    return re.findall(r"```(?:bash|sh|console)\n(.*?)```", section, re.S), section


def banned_in(text):
    found = []
    for word in BANNED:
        if re.search(r"\b%s\b" % word, text):
            found.append(word)
    for word in BANNED_ANYCASE:
        if re.search(r"\b%s\b" % word, text, re.IGNORECASE):
            found.append(word)
    return found


class AStrangerCanGetAFirstSuccess(unittest.TestCase):
    """Install the artifact, copy the README, get a real gated action. No checkout, no theory."""

    @classmethod
    def setUpClass(cls):
        wheels = sorted(DIST.glob("*%s*.whl" % declared_version())) if DIST.is_dir() else []
        if not wheels:
            raise unittest.SkipTest(
                "no built wheel for %s in dist/; run `python -m build` first" % declared_version())
        cls.room = pathlib.Path(tempfile.mkdtemp(prefix="stranger-"))
        environment = cls.room / "env"
        made = subprocess.run([sys.executable, "-m", "venv", str(environment)],
                              capture_output=True, text=True, timeout=300)
        assert made.returncode == 0, made.stderr
        installed = subprocess.run(
            [str(environment / "bin" / "pip"), "install", "--quiet", str(wheels[-1])],
            capture_output=True, text=True, timeout=900)
        assert installed.returncode == 0, installed.stderr
        cls.vfy = environment / "bin" / "vfy"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "room", "/nonexistent"), ignore_errors=True)

    def setUp(self):
        self.workspace = self.room / self.id().rsplit(".", 1)[-1]
        self.workspace.mkdir()

    def shell(self, script):
        """Run one README block the way a reader would: a shell, in an empty directory.

        `vfy` is put on PATH rather than substituted into the text, so the commands executed are
        the characters the README prints.
        """
        environment = dict(os.environ)
        environment["PATH"] = str(self.vfy.parent) + os.pathsep + environment["PATH"]
        environment.pop("PYTHONPATH", None)
        return subprocess.run(["/bin/sh", "-c", script], cwd=str(self.workspace),
                              capture_output=True, text=True, timeout=300, env=environment)

    def quickstart(self):
        """Run the whole quickstart the way a reader does: one shell session, blocks in order.

        Not one shell per block. The README's first block ends in `cd`, and a reader pasting into
        their terminal keeps that directory for everything after it; running each block in a fresh
        shell would test a journey nobody takes and would fail on the second command.
        """
        blocks, _section = quickstart_blocks()
        self.assertTrue(blocks, "the README quickstart contains no runnable block")
        # `pip install verify-run` is the one line a test must not run: it would reach the network
        # and would install a *published* artifact over the one under test.
        script = "set -e\n" + "\n".join(
            line for block in blocks for line in block.splitlines()
            if not re.match(r"\s*(python -m )?pip install", line))
        done = self.shell(script)
        self.assertEqual(done.returncode, 0,
                         "the README quickstart does not run as written:\n%s\n%s"
                         % (script, done.stdout + done.stderr))
        return done.stdout + done.stderr

    def project(self):
        """Wherever the quickstart put the workspace. Found, not assumed."""
        found = sorted(self.workspace.rglob(".vfy"))
        self.assertTrue(found, "the quickstart initialized no workspace")
        return found[0].parent

    def test_the_readme_quickstart_runs_from_a_clean_directory(self):
        transcript = self.quickstart()
        self.assertIn("ALLOW", transcript, "the quickstart never reaches a successful action")

    def test_the_first_success_leaves_a_receipt_the_stranger_can_replay(self):
        self.quickstart()
        receipts = sorted((self.project() / ".vfy" / "receipts").glob("r-*.json"))
        self.assertTrue(receipts, "the quickstart produced no receipt")
        listed = self.shell("cd %s && vfy receipts list" % self.project())
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("ALLOW", listed.stdout)
        replayed = self.shell("cd %s && vfy replay %s" % (self.project(), receipts[0]))
        self.assertEqual(replayed.returncode, 0, replayed.stderr)
        for phrase in ("signature verified", "recomputed and identical"):
            self.assertIn(phrase, replayed.stdout,
                          "replay does not tell the reader what it checked")

    def test_all_three_outcomes_are_reachable_and_readable(self):
        """ALLOW, BLOCK and HOLD from one workspace. Collapsing them is the defect this exists on."""
        self.quickstart()
        project = self.project()
        run = lambda branch: self.shell(
            "cd %s && vfy run --identity branch=%s -- bin/deploy.sh v1.2.3" % (project, branch))
        allowed = run("main")
        blocked = run("feature")
        evidence = project / "ci" / "last-test-result.sh"
        os.chmod(evidence, 0o600)                 # the tests can no longer be read
        held = run("main")
        os.chmod(evidence, 0o755)
        for label, done, outcome, code in (("allow", allowed, "ALLOW", 0),
                                           ("block", blocked, "BLOCK", 10),
                                           ("hold", held, "HOLD", 11)):
            with self.subTest(outcome=label):
                self.assertIn(outcome, done.stdout, done.stdout + done.stderr)
                self.assertEqual(done.returncode, code,
                                 "%s must exit %d so a script can branch on it" % (outcome, code))

    def test_the_stranger_never_reads_a_theory_word(self):
        """The zero-theory claim, checked against what a first-time reader actually sees."""
        _blocks, section = quickstart_blocks()
        self.assertEqual(banned_in(section), [],
                         "the README quickstart uses vocabulary this product does not expose")
        transcript = self.quickstart()
        for extra in ("vfy --help", "cd %s && vfy receipts list" % self.project()):
            transcript += self.shell(extra).stdout
        self.assertEqual(banned_in(transcript), [],
                         "the program says a word to the user that the product does not expose")

    def test_the_installed_artifact_answers_without_the_checkout(self):
        """A stranger has the wheel and nothing else. Nothing may resolve from this repository."""
        version = self.shell("vfy --version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertIn(declared_version(), version.stdout)
        located = self.shell(
            'python -c "import vfy, pathlib; print(pathlib.Path(vfy.__file__).resolve())"')
        self.assertNotIn(str(REPO_ROOT), located.stdout,
                         "the quickstart resolved code from the checkout, not the artifact")


if __name__ == "__main__":
    unittest.main()
