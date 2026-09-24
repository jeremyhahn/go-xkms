- **`pkg/acme` no longer silently discards `Close` errors reached through a
  deferred closure**: `#701` batch 3's grep only matched discards written at
  the start of a line, missing the ~85 sites shaped like
  `defer func() { _ = resp.Body.Close() }()` across the REST/QUIC/MCP API
  adapters, the CT-log submitter, the audit query reader, the DNS-01/HTTP-01/
  device-attest-01/enroll-01 challenge responders, the ACME client's chain,
  ARI and OCSP fetches, and the rate limiter's client-ID extraction. HTTP
  client response-body (and audit log file/gzip reader) closes, made after
  the read that produced the function's result has already succeeded, now
  log the close failure at debug through the package's logger instead of
  discarding it; the REST, QUIC and MCP adapters share one
  `api.CloseResponseBody` helper rather than repeating the same closure at
  every call site. Server-side `r.Body.Close()` calls are left as
  intentional, documented discards: net/http closes the server request body
  itself once the handler returns, so closing it again is a defensive no-op
  whose error is never meaningful. No behavior changes for the success path;
  previously-silent close failures are now visible. (go-xkms#866)
