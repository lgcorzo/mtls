# Changelog

All notable changes to `mtls` will be documented in this file.

## [v0.4.1-lgcorzo.4] - 2026-10-10

### Security & Infrastructure
- **Dependency & Toolchain Security**: Aligned build configurations and CI pipelines with standard Go 1.25 toolchain requirements.
- **Supply-Chain Hardening**: Updated `.github/workflows/ci.yml` action steps (`actions/checkout` and `actions/setup-go`) to pin immutable commit SHAs.
- **Static Code Analysis & Rule Hygiene**: Added `.semgrepignore` to prevent false positive credential findings on test data key vectors.
- **Input Validation & Safety Bounds**: Enhanced runtime bounds checking and bounds validation on RSA parameters, SSH agent payload framing, and integer conversions in `key.go`, `ssh/agent.go`, and `ssh/identity.go`.
