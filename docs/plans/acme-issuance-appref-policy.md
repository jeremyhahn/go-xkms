# acme-issuance: the application reference at finalize, on the handler and from config

Row: acme-issuance (docs/SPEC.md:41), epic #1667, slice 2 (lane sacmeib), stacked on 5d3244280.

## Gaps slice 1 left

1. No handler-level finalize test proves that `bindDeviceAttestationKey`
   refuses a mismatched or a required-but-absent application reference.
2. `DICEPolicy.RequireApplicationReference` has no xkmsd config key:
   `buildDeviceAttestVerifier` (cmd/xkmsd/acme_device_attest.go) passes only
   the three other DICE flags.

## Names

- Config field `ACMEDeviceAttestConfig.DICERequireApplicationReference bool`,
  yaml `dice_require_application_reference`.
- Test `TestBindDeviceAttestationKey_ApplicationReference` in
  pkg/acme/server/handlers/device_attest_appref_test.go, helper
  `newRequiringRegistry(t, service)`.
- No new sentinel, error type or SDK name.

## Files

- pkg/acme/server/handlers/device_attest_appref_test.go (new)
- pkg/config/acme.go, pkg/config/acme_device_attest_test.go
- cmd/xkmsd/acme_device_attest.go
- docs/acme-issuance/engineering.md
- .changelog/unreleased/added-1667-acme-dice-require-application-reference.md

## Checks

- go test -race (codec tags) ./pkg/acme/server/handlers/... ./pkg/acme/challenges/device-attest-01/... ./pkg/config/...
- go test -race -run DeviceAttest ./cmd/xkmsd/
- sdk/go: go build ./...
- make lint

## Results

Results to follow.
