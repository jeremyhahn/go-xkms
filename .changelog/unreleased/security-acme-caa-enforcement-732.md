- **RFC 8659 CAA is now enforced at ACME finalize — BREAKING.** The seam
  (`Params.CAAValidator`, `pkg/acme/server/handlers/service.go`) already
  existed and `order_finalize.go` already consulted it, but nothing ever
  constructed a validator: `NewCAAValidator` had no caller, so every ACME
  issuance path (xkmsd, and the standalone `TrustedCA` merged from
  go-trusted-ca) skipped CAA checking regardless of what a domain's CAA
  records said, despite the directory advertising `caa_identities`.
  `cmd/xkmsd/acme.go` and `pkg/acme/client/trustedca.go` now each build a
  `*server.CAAValidator` via `server.NewCAAValidator` (the one construction
  path; also re-exported as `sdk/go/acme.NewACMECAAValidator` for SDK
  consumers composing their own `RestService`) and set it on
  `handlers.Params.CAAValidator` before constructing the REST service.
  `ACMEConfig.CAAIdentities` (`acme.caa_identities`, already present for
  directory advertisement) is now **required whenever `acme.enabled` is
  true** — `Validate` returns `ErrACMEMissingCAAIdentities` otherwise, so a
  deployment can no longer silently advertise CAA support it never enforced.
  The standalone `TrustedCA`'s `TCAACMEConfig.CAIdentifiers` gets the same
  `Validate` rule, though `TrustedCA.Serve` only warns (not required, to
  avoid changing that library's start-up contract) since the validator
  itself now fails closed for any domain that actually publishes a CAA
  record. Both composition paths also gained `caa_dns_server` /
  `CAADNSServer` to optionally pin the resolver; unset reuses the same
  default the `dns-01` challenge tooling already uses
  (`pkg/acme/challenges/dns-01/providers.DefaultNameservers[0]`) instead of
  a second hardcoded literal.

  `pkg/acme/server/caa.go` itself had several RFC 8659 gaps, all fixed with
  tests (`pkg/acme/server/caa_test.go`,
  `pkg/acme/server/handlers/caa_finalize_test.go`): (1) a DNS lookup failure
  (SERVFAIL, timeout, any non-NXDOMAIN error) used to "proceed with
  caution" and allow issuance — RFC 8659 Section 5.1 requires the opposite,
  fail closed, since the CA cannot determine the relevant CAA RRset; (2)
  `isAuthorized` compared a CAA record's issuer-domain-name with
  `strings.HasPrefix`, so an identity `ca.example.com` incorrectly
  authorized a record naming `ca.example.com.attacker.example` — issuer
  matching is now an exact, case-insensitive full-domain comparison, with
  RFC 8657 `accounturi`/`validationmethods` parameters correctly parsed out
  of the value first rather than accidentally tolerated by the prefix bug;
  (3) an unrecognized property tag carrying the critical flag (RFC 8659
  Section 4) was ignored instead of blocking issuance; (4) a validator with
  no configured identities silently allowed issuance in the presence of an
  actual CAA record instead of failing closed. go-xkms#732.
