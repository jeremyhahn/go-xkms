// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"errors"

	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// buildSecretRegistry constructs the server's secret resolver registry for
// resolving URI-addressed secrets at startup. When the credential service
// is available, a credential:// resolver backed by that service is registered.
// Literal passthrough is automatic via the registry's fallback behaviour.
//
// The CA is system-scoped, so only the system credential service is wired here;
// per-tenant credential routing is not required for CA key passwords.
func (s *Server) buildSecretRegistry() *qrdbsecret.ResolverRegistry {
	reg := qrdbsecret.NewResolverRegistry()
	if svc := s.CredentialService(); svc != nil {
		reg.Register(qrdbsecret.NewCredentialResolver(svc.RetrieveCredential))
	}
	return reg
}

// resolveConfigSecrets runs go-qrdb's canonical ConfigProcessor once over the
// entire loaded configuration (s.config), the single resolution point for
// every *types.SecretValue field reachable from it: the CA identity and
// software-keystore passwords, the cluster CA key passphrase, and the phone
// backend's Noise static key all resolve here now, in place of their own
// former buildSecretRegistry().Resolve call.
//
// go-xkms#654 originally declared every secret-bearing config field as a
// VALUE types.SecretValue and had this function swallow the resulting
// qrdbsecret.UnresolvableTargetError as a tolerated "nothing to resolve
// here" outcome -- a divergence from go-qrdb's own contract
// (pkg/secret/walker.go), under which a value-typed protected target is
// ALWAYS required (an empty one fails the walk) and an optional secret can
// only be spelled as a nil *SecretValue, which the walker skips before ever
// producing an error. go-xkms#653/#654 corrected the field declarations
// (every one is now *types.SecretValue; nil means unconfigured), which is
// what makes this function's contract now correct: every remaining error
// ConfigProcessor reports is a genuine failure -- a configured-but-
// unresolvable reference (an inline "literal://" secret, a bare value, or an
// unclaimed scheme, all of which a protected target refuses by design), or a
// resolver that was claimed but failed -- and none of it may be suppressed.
// An unconfigured (nil) field never reaches Process as an error at all: the
// walker's own reflect.Pointer case skips a nil pointer before it becomes a
// protected-target failure, which is the qrdb contract's ONLY silent case.
//
// Server.New now runs this call BEFORE initializeBackends (go-xkms#653's
// approved item 2), so this is also the resolution point for the five
// backend-credential fields that used to be read too early to benefit:
// backends.pkcs11.pin, rng.pkcs11.pin, backends.awskms.secret_key,
// backends.azurekv.client_secret, and backends.vault.token. A credential://
// reference for any of them now resolves here exactly like a CA password or
// the phone backend's Noise static key; TestBackendCredentials_ResolveViaCredentialReference
// (secret_wiring_test.go) proves all five end to end.
//
// This ordering is possible without a cycle against initializeBarrier's own
// hardware seal strategies (buildHardwareSealStrategies, built from
// already-initialized backends in s.keyProviders) because that path is now
// reached only for a barrier strategy BarrierConfig.NodeFlipWired reports
// false for (pkcs11 and the cloud-KMS strategies) — see resolveNodeSeal and
// NodeFlipWired's doc. The strategy this call's own ordering exists to
// serve, tpm2, is built by resolveNodeSeal directly from Backends.TPM2
// config (never from s.keyProviders) and injected into the qrdb node's own
// seal subsystem before this call ever runs, so it has no dependency on
// backend initialization at all. There is no equivalent caveat for the
// barrier's own boot secret any more: go-xkms#653 removed the
// config-sourced BarrierConfig.Passphrase field entirely, so the barrier
// never auto-unseals from configuration at all -- it auto-unseals through a
// registered hardware seal strategy (tpm2 today), or blocks Server.New at
// initializeQRDBStorage behind the sealed-window listener for an operator
// to unseal via `xkmsctl barrier unseal`/`unseal-shares`/the equivalent
// API call (mirroring go-qrdb's own cmd/qrdbd initSealSubsystem ->
// awaitUnseal sequence, driven entirely through go-qrdb/sdk/go).
//
// A PKCS#11 barrier strategy remains genuinely impossible: it would need
// the same already-initialized PKCS#11 backend buildHardwareSealStrategies
// reads from s.keyProviders, which initializeBackends now builds AFTER
// this call — the same cycle as before, just narrowed to the one strategy
// (and the cloud-KMS strategies) NodeFlipWired excludes. That is a
// pkg/seal/pkg/server/types.Sealer interface change (letting a barrier
// strategy accept a deferred, per-call credential the way the software
// strategy already does), not a reorder, and is not approved.
func (s *Server) resolveConfigSecrets() error {
	reg := s.buildSecretRegistry()
	proc := qrdbsecret.NewConfigProcessor(reg)
	result, err := proc.Process(s.ctx, s.config)
	if err == nil {
		return nil
	}

	// err is qrdbsecret.ErrUnresolvedSecretURI, go-qrdb's own typed sentinel,
	// unmodified -- propagated via errors.Join alongside result.Errors (the
	// per-field detail: which path, which typed cause) so both the sentinel
	// and the field-level typed errors (UnresolvableTargetError,
	// ResolutionFailedError, UnwritableTargetError, MaxDepthExceededError)
	// remain reachable through errors.Is / errors.As. Nothing here filters,
	// tolerates or reinterprets any of it.
	return &ErrConfigSecretResolution{Err: errors.Join(append([]error{err}, result.Errors...)...)}
}
