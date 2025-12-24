# VirtualFIDO Security Key Implementation Checklist

Wrapping [github.com/bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido)

## Phase 1: Add Dependency & Backend Foundation

- [ ] Add `github.com/bulwarkid/virtual-fido` to go.mod
- [ ] `pkg/backend/virtualfido/config.go` - Configuration (with storage.Backend)
- [ ] `pkg/backend/virtualfido/storage_adapter.go` - Adapts storage.Backend to virtual-fido
- [ ] `pkg/backend/virtualfido/slots.go` - PIV slots
- [ ] `pkg/backend/virtualfido/backend.go` - Backend wrapping virtual-fido
- [ ] `pkg/backend/virtualfido/signer.go` - crypto.Signer
- [ ] `pkg/backend/virtualfido/decrypter.go` - crypto.Decrypter
- [ ] `pkg/backend/virtualfido/symmetric.go` - SymmetricBackend
- [ ] `pkg/backend/virtualfido/keyagreement.go` - KeyAgreement
- [ ] `pkg/backend/virtualfido/attestation.go` - AttestingBackend
- [ ] `pkg/backend/virtualfido/keyops.go` - Key-specific operations (PIN/PUK/MgmtKey)
- [ ] Unit tests for backend operations

## Phase 2: FIDO2 Device Adapter Layer

- [ ] `pkg/fido2/virtual_approver.go` - Auto-approver for tests
- [ ] `pkg/fido2/virtual_device.go` - Adapter wrapping virtual-fido
- [ ] `pkg/fido2/virtual_enumerator.go` - Enumerator
- [ ] Unit tests for FIDO2 adapter

## Phase 3: HMAC-Secret Extension

- [ ] Check virtual-fido hmac-secret support
- [ ] Implement or fork if needed
- [ ] Integration tests

## Phase 4: Integration & Tests

- [ ] Backend <-> FIDO2 device wiring
- [ ] Update `test/integration/fido2/testutil.go`
- [ ] `test/integration/virtualfido/` tests
- [ ] Verify all FIDO2 tests pass

## Phase 5: Documentation

- [x] `docs/virtualfido/README.md`
- [ ] `docs/virtualfido/implementation-plan.md`
- [x] `docs/virtualfido/implementation-checklist.md`
- [ ] `docs/virtualfido/architecture.md`
- [ ] `docs/virtualfido/usage.md`
- [ ] `docs/virtualfido/piv-operations.md`
- [ ] `docs/virtualfido/fido2-operations.md`
- [ ] `docs/fido2/virtualfido-device.md`
- [ ] Update `docs/fido2/README.md`
