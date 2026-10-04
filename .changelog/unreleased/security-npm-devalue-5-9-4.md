- **The web console and ACME web UI lockfiles pin devalue 5.9.4.** Trivy
  flagged devalue 5.8.1/5.9.0 (CVE-2026-92708 and three GHSAs, fixed in
  5.9.3), a transitive dependency of svelte in `pkg/acme/web` and `web/app`.
