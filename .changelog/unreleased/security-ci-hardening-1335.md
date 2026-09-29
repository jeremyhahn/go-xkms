---
area: ci
scope: github-actions
---

# GitHub Actions Security Hardening

- Pin all third-party GitHub Actions to full 40-character commit SHAs instead of version tags
- Add top-level `permissions: contents: read` to CI workflow with granular job-level overrides
- Add `persist-credentials: false` to all `actions/checkout` steps to reduce credential exposure
- Pass workflow outputs through environment variables instead of direct template interpolation to prevent injection attacks
- Pin container images by digest for build stages and security scanning tools
