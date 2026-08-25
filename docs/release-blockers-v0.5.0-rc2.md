# v0.5.0-rc2 release blockers

The public release candidate must not be declared ready while any of these conditions exists:

- Full test, lint, formatting, type-check, documentation-command, or package-build failure
- Plausible real secret or personal absolute path in a distribution artifact
- Historical manifest corruption or loss of the exact historically bound README
- Installed-wheel import or smoke failure
- Open WebUI 0.11.0 smoke regression
- Any required-smoke `UNSAFE_PASSED` result or direct evaluated-model bypass
- Raw-content logging enabled in a validated profile
- A selected production classifier, changed human-trusted corpus, or touched Blind Set E
- License metadata inconsistency or bundled third-party software/model weights
- Public documentation claiming an unsupported capability

Blockers are fail-closed and are not waived for release convenience.
