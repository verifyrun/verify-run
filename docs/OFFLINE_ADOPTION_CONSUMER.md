
## Installed distribution gate

`tools/check_installed_offline.py --module-sha256 <independently-selected-source-sha256>`
checks the installed module through the selected Python with isolated imports from a temporary directory. It refuses a mismatched module pin and requires the CLI to refuse an incorrect policy digest and missing original inputs. The CI artifact job builds and installs wheel and source distributions on Linux and macOS with Python 3.11–3.13 before running these controls. A configured job is not evidence of a successful hosted run.

These entry controls do not verify a positive receipt, authorize a trust key, establish complete dependency provenance, or authorize publication. Positive retained-receipt verification remains a separate acceptance test. Select the module pin from the reviewed source revision, not from the artifact being tested.
