---
area: release
scope: release-engineering
---

# Release Tag Signature Verification and Asset Integrity

- Add signature verification for release tags using `git verify-tag` with SSH public key allowlist
- Create `.github/allowed_signers` file for authorized release signing keys (owner must populate with public keys)
- Restrict `workflow_dispatch` to main branch only to prevent accidental releases from other branches
- Modify `scripts/release-assets.sh` to fail with clear error on asset digest mismatch instead of silently replacing assets
- Add SBOM (Software Bill of Materials) generation for release artifacts using syft with checksum verification
