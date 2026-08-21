## Summary

Describe the user-visible behavior and why this change is needed.

## Correctness and compatibility

Explain effects on cache eligibility, action keys, dependency tracking, manifests, output materialization, and existing cache entries. Write "Not applicable" when none apply.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all-targets`
- [ ] Focused or differential coverage was added when compiler behavior changed.
- [ ] Documentation and `CHANGELOG.md` were updated for user-visible changes.

List the operating systems and `gfortran` versions used for testing, plus any remaining limitations.
