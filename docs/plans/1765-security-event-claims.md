# 1765: the security-event Claims-Set and the AttestSecurityEvents capability

Objective: SPEC row `device-security-event-evidence` (docs/SPEC.md:88) names
one optional backend capability and a Claims-Set format for the device
tamper-response record (docs/attestation-evidence/architecture.md, "Device
security-event record"). Main has neither. This slice adds both. It does not
decide the binding question (a)/(b)/(c), and no backend implements the
capability yet.

## Types

- `securityevent.Record{Count uint8, Dropped uint16, Entries []Entry}`
- `securityevent.Entry{At uint32, Kind, What, Result uint8}`
- Widths are the reply widths in the architecture table (`count:1`,
  `dropped:2`, `at:4`, `kind:1`, `what:1`, `result:1`).
- `types.SecurityEventProvider`: embeds `KeyProvider` and adds
  `AttestSecurityEvents(ctx, nonce) ([]byte, error)`, which returns the
  encoded Claims-Set, or `backend.ErrNotSupported` when the backend keeps
  no record.

## CBOR keys

RFC 8949 §4.2.1 core deterministic encoding, integer keys only.

- Claims-Set: `{ClaimKey: record}`. `ClaimKey` is -71765, which is in the CWT
  private-use range (RFC 8392 §9.1, keys below -65536). It is go-xkms's own
  until EAT registers a claim for the record.
- record: `{1: count, 2: dropped, 3: [entry, ...]}`
- entry: `{1: at, 2: kind, 3: what, 4: result}`

## Checks (Decode refuses, each with a typed error)

- not well-formed CBOR, a duplicate key, a tag, or the wrong shape: `ErrMalformed`
- a key the format does not define: `ErrUnknownKey`
- a member missing: `ErrMissingKey`
- a value too wide for its field: `ErrOutOfRange`
- `len(Entries) != Count`: `ErrCountMismatch`
- input that is not the deterministic encoding of what it decodes to:
  `ErrNotDeterministic`

Encode refuses `len(Entries) != Count` with `ErrCountMismatch`.

## Slices

1. This plan (docs(plans)).
2. Test commit: round trip, a pinned byte vector with its derivation, each
   refusal, `Dropped` at 0xFFFF and 0x10000, an empty record, and the
   compile-time assertion for `types.SecurityEventProvider`.
3. Feat commit: `pkg/attestation/securityevent` and the interface; the
   architecture.md Hook paragraph; a changelog entry.

Out of scope: a backend implementation, a transport, the binding (signing,
digest, nonce check), docs/SPEC.md.

## Results to follow

