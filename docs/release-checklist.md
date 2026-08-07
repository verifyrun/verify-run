# Release checklist

A step is marked done only when it has actually been performed. Nothing below is aspirational.

## Ready

- [x] Version `0.1.0a2`, one authoritative source, asserted by test.
- [x] License decided (Apache-2.0), `LICENSE` and `NOTICE` present, declared in metadata.
- [x] Full suite passing, including under hostile locale, timezone, hash-seed, and UTF-8 settings.
- [x] Vocabulary gate committed and running in the suite.
- [x] Legacy-reference gate committed.
- [x] Secret gate committed.
- [x] `.gitignore` frozen; no key material, workspace, or credential can be tracked.
- [x] Wheel and source distribution build.
- [x] Package contents inspected against a frozen expectation.
- [x] Clean install from the wheel completes the whole workflow outside the repository.
- [x] Clean install from the source distribution completes the same workflow.
- [x] Installed runtime resolves its schemas and templates inside the installed package.
- [x] README and quickstart transcripts captured from real output.
- [x] Documented rulebooks and expressions parse under the real parser, asserted by test.
- [x] CI workflow written, read-only permissions, no publication token.
- [x] Git repository initialized.

## 0.1.x final hardening pass — done

- [x] Full suite passing, including under hostile locale, timezone, hash-seed, and UTF-8 settings.
- [x] Conformance kit PASS 30/30 against this source **and** against the published `0.1.0a2`
      distribution installed from production PyPI, with an unchanged profile, an unchanged fixture
      manifest digest, and 30 byte-identical fixture bundles.
- [x] Receipts written by published `0.1.0a2` replay under this source, and receipts written by
      this source replay under published `0.1.0a2`, in the same store.
- [x] Clean install from the wheel completes the whole workflow outside the repository.
- [x] Vocabulary, legacy-reference, and secret gates passing.
- [x] CI job added that builds the distribution, installs it clean, and runs the full conformance
      kit; anything but PASS fails the job, INCOMPLETE included.

## Remaining before a `0.1.0a3` release

- [ ] **Bump the version** to `0.1.0a3` in `pyproject.toml`, and retitle the CHANGELOG section.
      Deliberately not done during the hardening pass: `vfy --version` would otherwise claim a
      version nobody can install.
- [ ] **Move `PIN` in `tools/conformance_reference_run.sh`** to the newly published version, once
      it is on PyPI. It is the published reference run and must install from PyPI, not from here.
- [ ] **Decide on `profile.json`'s `reference_implementation.version`.** Changing it changes the
      profile digest, which is contract drift — so it moves only with a deliberate profile
      version, never as a side effect of a package release.

## Remaining, and who must do it

- [ ] **Commit.** Nothing has been committed. Requires explicit authorization.
- [ ] **Create the GitHub repository** and push. Requires authorization; the CI workflow assumes
      GitHub Actions and has not run anywhere yet.
- [ ] **Confirm the PyPI name `verify-run` is available or already controlled.** This cannot be
      determined offline. The npm placeholder under `verify-run/` reserves the npm name only, and
      is excluded from the Python distribution.
- [ ] **Confirm the GitHub repository name and owner.**
- [ ] **TestPyPI upload** and an install from it into a clean environment.
- [ ] **Real PyPI upload.** Prefer a trusted-publisher configuration over a long-lived token; if a
      token is used it belongs in a repository secret and never in the workflow file.
- [ ] **Tag** `v0.1.0a2` after the commit exists.
- [ ] **Set repository visibility** deliberately — public alpha or private release candidate.
- [ ] Verify the CI matrix actually passes on 3.11, 3.12, and 3.13; it has only been reasoned
      about locally, since only 3.14 is installed on the development machine.
- [ ] Decide whether `CONTRIBUTING.md` and `SECURITY.md` are needed before the repository is
      public.
- [ ] Announcement, if any.

## Not in this release, and the docs say so

HTTP evidence, `watch`, `serve`, hosted registry or vault, fleets, accounts, billing, a browser
interface, the device pack, and the npm runtime.
