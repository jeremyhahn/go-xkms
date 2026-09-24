- **`acme.reuse_tls` deleted — BREAKING.** The ACME listener's `ReuseTLS`
  config field never worked: `buildACMETLSConfig` (`cmd/xkmsd/acme.go`)
  refused it at start-up with "not yet supported" rather than actually
  reusing the primary xkmsd TLS material, and the "follow-up" comments
  promising that support are gone too — the xkmsd TLS stack is authenticated
  against the xkmsd REST/gRPC server CN and would generally not match an
  ACME client's expected hostname, so there is no reuse path to build. The
  ACME listener now unconditionally requires its own dedicated
  `acme.tls.cert_file`/`acme.tls.key_file` pair whenever `acme.enabled` is
  true (`ErrACMEMissingTLS`, `pkg/config/acme.go`). A configuration file or
  environment variable (`XKMS_ACME_REUSE_TLS`) that still sets
  `acme.reuse_tls` now fails to load with a typed
  `*config.RemovedFieldError{Field, Replacement}` instead of the key being
  silently dropped, via the general `removedConfigFields`/
  `rejectRemovedFields` mechanism go-xkms#653 introduced for
  `barrier.passphrase` (`pkg/config/load.go`). Files: `pkg/config/acme.go`,
  `pkg/config/load.go`, `pkg/config/load_test.go`, `cmd/xkmsd/acme.go`,
  `cmd/xkmsd/acme_test.go`, `docs/acme-issuance/engineering.md`. go-xkms#694.
