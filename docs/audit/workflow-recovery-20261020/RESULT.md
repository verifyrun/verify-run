# Installed workflow interruption and recovery

Parent source8627ddd, runtime remains byte-identical to E18 Run4f9361a.
Three fresh disposable workflows exercised actual installed `vfy service-workflow`
subprocesses. Kill occurred after durable reservation, admission and consumption.
A separate installed recovery command preserved the original reservation and
completion, consumed recovery once, and granted neither action authority nor
construction continuation. Subsequent recovery/session/adopt commands refused and
left the exact state digest unchanged. No retained customer attempt was executed.

Installed console: /private/tmp/verify-run-release-installed-20261020/bin/vfy
Installed library: that environment's lib/python3.14/site-packages/vfy.
Package wheel SHA25655aa33f5f6cd0f93b0e9c2c573878854aec528ec2f0516c4d610ab9bc6b66b8f.
Tests use existing disposable source fixture constructors and actual installed
runtime/console, not a replacement implementation. Three installed tests passed;
see INSTALLED.txt. Source initial run passed these three plus six existing fixture
tests. Fixture import was subsequently narrowed to avoid duplicate collection.

This is scoped interrupted-flow evidence, not full W10/customer acceptance.
No actual child program ran: CONSUME uses the existing fresh fixture START witness.
Full physical resource accounting stays UNKNOWN. Post-effect interruption,
Platform task association, hosted pair acceptance and whole launch remain open.
No runtime schema or source changed; no production or public release performed.
