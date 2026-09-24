- **`pkg/acme` no longer drops error returns it can act on**: audit-logging,
  serial-revocation, DNS/challenge cleanup, TPM-open cleanup, and Unix-socket
  cleanup failures are now joined into the caller's error or reported through
  the package's `slog` logger instead of being silently discarded with `_`;
  CT-log submission failures are collected and surfaced in the policy
  violation returned when a certificate can't get enough SCTs; an unknown-type
  JWK comparison in external-account-binding verification no longer treats a
  `json.Marshal` failure as a false "keys match"; a tenant-aware admin
  service whose storage factory fails to produce its tenant DAO now logs the
  failure instead of silently degrading with no diagnostic; and HTTP
  handlers across `pkg/acme` now log a failed response write instead of
  ignoring it, since headers are already sent by that point and there is no
  way to report the failure to the client. No behavior changes for the
  success path; several previously-silent failure paths are now visible.
  (go-xkms#701 batch 3)
