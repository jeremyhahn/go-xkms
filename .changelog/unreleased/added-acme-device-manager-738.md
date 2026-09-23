- **Implemented the ACME device enrollment and attestation path end to end
  — BREAKING.** `pkg/acme/client/service` gains a `DeviceManager`
  (`Enroll`/`Attest`/`List`/`Show`) alongside `AccountManager` and
  `CertificateManager`, keyed by a new `Config.Devices` map of named
  `DeviceSpec`s (account, common name, ACME permanent identifier, PCR
  selection, local challenge server bind, and a `DeviceTPMConfig` that
  reuses go-xkms's own `TPMConfig` wholesale so device identity keys are
  always TCG-provisioned, never invented locally). The manager opens and,
  for the in-process simulator only, provisions the TPM (EK, SSRK, IAK, and
  a throwaway EK certificate when none exists) before driving the existing
  `client.EnrollDevice`/`client.DeviceAttest` over enroll-01 /
  device-attest-01 — real hardware is never auto-provisioned. The GUI's
  `POST /api/v1/device/{enroll,attest}` handlers (previously 501) and
  `trusted-acme-client device {enroll,attest} <name>` (previously a
  flag-based no-op) now resolve a device spec by name through this service,
  matching the certificate verbs' shape; the old `--account`/`--device-id`
  free-form CLI flags are gone. `pkg/testutil` gains `FakeACMEDirectory`, a
  reusable in-process ACME v2 directory for exercising
  `golang.org/x/crypto/acme.Client`-based flows without a live CA. Fixes
  go-xkms#738.