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
	"context"
	"errors"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	sealedstorage "github.com/jeremyhahn/go-xkms/pkg/storage/sealed"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// platformStoreSealCN is the well-known common name of the TPM-resident
// sealed object the platform store's tpm2 strategy creates. It is distinct
// from the barrier's own "platform-sealing-key" default (pkg/tpm2's
// defaultSealKeyAttributes) so the two never collide when both are in use on
// the same TPM.
//
// The cloud-KMS strategies (awskms/gcpkms/azurekv) do not need an equivalent
// constant: they reuse seal_strategies.go's sealKeyAttributesFor, keyed to
// the barrier's own sealKeyCN. A cloud CMK is not a per-purpose object the
// way a TPM-sealed blob is, so the barrier and the platform store sharing
// one self-provisioned CMK per cloud is deliberate reuse, not a collision.
const platformStoreSealCN = "xkms-platform-store-seal"

// initializePlatformStore builds the platform sealed credential store
// (pkg/seal.PlatformStore) from credentials.seal_strategy and assigns it to
// s.platformStore. It runs after unseal (see the call site in Server.New):
// for a node-flip deployment the node's own barrier is already adopted by
// this point; for every other deployment the platform store does not depend
// on s.barrier at all -- it seals independently, through its own strategy.
//
// "manual" (the default) and "barrier" are skipped: manual never stores a
// credential at rest, and "barrier" stores directly in s.barrier via
// credentials.Service, bypassing the platform store entirely (see
// pkg/server/credentials.Service.StoreCredential). Every other valid
// strategy (tpm2, pkcs11, awskms, gcpkms, azurekv, vault, passphrase) is
// backed by the platform store built here.
//
// A strategy this cannot build a sealer for fails startup with a typed
// error -- never a silent skip -- because credentials.Service refuses that
// strategy's Put/Get with ErrNilPlatformStore, and discovering that only at
// first credential use (rather than at boot) is exactly the failure this
// issue (go-xkms#718) exists to close.
func (s *Server) initializePlatformStore() error {
	strategy := s.config.Credentials.SealStrategy
	if strategy == "" {
		strategy = "manual"
	}
	if strategy == "manual" || strategy == "barrier" {
		s.logger.Info("Platform store skipped: strategy does not use the platform store", "strategy", strategy)
		return nil
	}

	sealer, err := s.buildPlatformSealer(strategy)
	if err != nil {
		return &ErrPlatformStoreBuild{Strategy: strategy, Err: err}
	}

	id := seal.StrategyID(strategy)
	platformSealer, err := seal.NewPlatformSealer(
		s.logger,
		seal.SealerConfig{PreferenceOrder: []seal.StrategyID{id}},
		map[seal.StrategyID]types.Sealer{id: sealer},
	)
	if err != nil {
		return &ErrPlatformStoreBuild{Strategy: strategy, Err: err}
	}

	inner, err := s.createStorage("platform-store")
	if err != nil {
		return &ErrStorageCreate{Resource: "platform store storage", Err: err}
	}

	sealedBackend, err := sealedstorage.New(inner, platformSealer, nil)
	if err != nil {
		return &ErrPlatformStoreBuild{Strategy: strategy, Err: err}
	}

	store, err := seal.NewPlatformStore(sealedBackend, s.logger)
	if err != nil {
		return &ErrPlatformStoreBuild{Strategy: strategy, Err: err}
	}

	s.platformStore = store
	s.logger.Info("Platform store initialized", "strategy", strategy)
	return nil
}

// buildPlatformSealer resolves the types.Sealer the platform store seals
// through for the given credentials.seal_strategy.
func (s *Server) buildPlatformSealer(strategy string) (types.Sealer, error) {
	switch strategy {
	case "tpm2":
		return s.buildTPM2PlatformSealer()
	case "passphrase":
		// Owner ruling (pending): there is no config field carrying an
		// operator passphrase for credentials.seal_strategy
		// (CredentialsConfig has only SealStrategy), and a literal/inline
		// secret in a protected *types.SecretValue field is refused by the
		// qrdb secret-value contract -- so this strategy cannot derive a
		// real seal without either new config surface or a design the owner
		// has not yet chosen. A previous version of this code generated a
		// random secret and persisted it UNSEALED next to the data as a
		// stand-in; that is not sealing, so it was removed. Fail closed
		// until the owner rules on where the passphrase comes from.
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: strategy,
			Reason: "an operator passphrase source for credentials.seal_strategy: " +
				"passphrase is not yet configurable; owner ruling pending -- see " +
				"go-xkms#718",
		}
	case "pkcs11":
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: strategy,
			Reason: "the PKCS#11 User PIN is only resolvable through a credential:// " +
				"reference, which requires the credential service this call itself " +
				"builds the storage for -- sealing the PIN with the PIN it unlocks " +
				"is a genuine cycle, not a gap in this change; see go-xkms#677",
		}
	case "vault":
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: strategy,
			Reason: "the Vault token is only resolvable through a credential:// " +
				"reference, which requires the credential service this call itself " +
				"builds the storage for; see go-xkms#677",
		}
	case "awskms":
		return s.buildAWSKMSPlatformSealer()
	case "gcpkms":
		return s.buildGCPKMSPlatformSealer()
	case "azurekv":
		return s.buildAzureKVPlatformSealer()
	default:
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: strategy,
			Reason:   "unrecognized credentials.seal_strategy",
		}
	}
}

// buildTPM2PlatformSealer resolves the types.Sealer for the tpm2 credential
// strategy. When the node-seal flip already opened a TPM (s.nodeSealTPM,
// pkg/server/node_seal.go), that single open is reused -- a second
// independent open hangs a swtpm emulator and is exactly what
// seal.BuildBestStrategy's own doc warns against. Otherwise a fresh probe is
// made directly from Backends.TPM2 via seal.BuildBestStrategy, the same
// autodetect pkg/seal already provides for the node-barrier flip and for
// go-quicbaas/xkey; its result's Close is tracked in
// s.platformStoreTPMClose for release at shutdown.
//
// go-xkms never seals under the TCG Shared SRK (SSRK): the Platform SRK
// (auth value the operator's PIN, authPolicy the platform PCR state) is the
// only parent this uses, matching PR #681's model. Enrolling the Platform
// SRK (pkg/tpm2's PlatformKeyStore.EnrollPlatformSRK) is a separate,
// deliberate operator/ceremony action -- not something a credential-strategy
// sealer performs implicitly on every boot -- so when it is not yet
// enrolled, TPM.PlatformSRKAttributes() reports it and this fails closed
// with a typed error rather than falling back to any other key. The
// returned sealer additionally binds every seal/unseal to the configured
// platform PCR (Backends.TPM2.PlatformPCR/PlatformPCRBank) when
// Backends.TPM2.PlatformPolicy is set, via platformPolicySealer.
func (s *Server) buildTPM2PlatformSealer() (types.Sealer, error) {
	backend, ok := s.nodeSealTPM.(*tpm2backend.Backend)
	if !ok {
		if s.config.Backends.TPM2 == nil || !s.config.Backends.TPM2.Enabled {
			return nil, &ErrPlatformStoreStrategyUnavailable{
				Strategy: "tpm2",
				Reason:   "backends.tpm2 is not configured/enabled",
			}
		}
		keyDir, err := s.resolveTPM2KeyDir()
		if err != nil {
			return nil, err
		}
		res := seal.BuildBestStrategy(seal.AutodetectOptions{
			TPM2: &seal.TPM2ProbeConfig{
				Device:          s.config.Backends.TPM2.DevicePath,
				KeyDir:          keyDir,
				UseSimulator:    s.config.Backends.TPM2.UseSimulator,
				SimulatorHost:   s.config.Backends.TPM2.SimulatorHost,
				SimulatorPort:   s.config.Backends.TPM2.SimulatorPort,
				SRKHandle:       s.config.Backends.TPM2.SRKHandle,
				PlatformPolicy:  s.config.Backends.TPM2.PlatformPolicy,
				PlatformPCR:     s.config.Backends.TPM2.PlatformPCR,
				PlatformPCRBank: s.config.Backends.TPM2.PlatformPCRBank,
			},
			Logger: s.logger,
		})
		if !res.HardwareAvailable() {
			return nil, &ErrPlatformStoreStrategyUnavailable{
				Strategy: "tpm2",
				Reason:   "no usable, provisioned TPM was found",
			}
		}
		tpmBackend, ok := res.Sealer.(*tpm2backend.Backend)
		if !ok {
			return nil, errors.Join(&ErrPlatformStoreStrategyUnavailable{
				Strategy: "tpm2",
				Reason:   "seal autodetect returned an unexpected sealer type",
			}, res.Close())
		}
		backend = tpmBackend
		s.platformStoreTPMClose = res.Close
		s.logger.Info("Platform store: opened a standalone TPM for the tpm2 credential strategy")
	} else {
		s.logger.Info("Platform store: reusing the node-seal flip's TPM open for the tpm2 credential strategy")
	}
	s.platformStoreTPM = backend

	psrkAttrs, err := backend.TPM().PlatformSRKAttributes()
	if err != nil {
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: "tpm2",
			Reason: "the Platform SRK is not enrolled: go-xkms seals under the " +
				"Platform SRK only, never the Shared SRK; enroll it first " +
				"(pkg/tpm2's PlatformKeyStore.EnrollPlatformSRK) -- see go-xkms#681 " +
				"-- underlying error: " + err.Error(),
		}
	}
	// PlatformSRKAttributes() already resolves PlatformPolicy from
	// configuration (pkg/tpm2/key.go), the same PlatformSRKAttributesFromConfig
	// a go-xkms Platform SRK is always created from -- both this backend's
	// autodetected Platform SRK (pkg/backend/tpm2/config.go's ToTPMConfig) and
	// the one PlatformKeyStore.Initialize/EnrollPlatformSRK enrolls now set
	// PlatformSRK.PlatformPolicy: true unconditionally, per the go-xkms#677
	// design (authValue = user PIN, authPolicy = platform PCR policy). Forcing
	// it true here regardless of that resolved value was itself the
	// go-xkms#997 defect: it let this sealer report a policy-gated PSRK even
	// when the object was created without one, hiding a real shape mismatch
	// instead of surfacing it.
	return &platformPolicySealer{
		inner:          backend,
		cn:             platformStoreSealCN,
		psrkAttrs:      psrkAttrs,
		platformPolicy: s.config.Backends.TPM2.PlatformPolicy,
	}, nil
}

// platformPolicySealer wraps a raw TPM2 types.Sealer so every Seal/Unseal
// call is parented to the enrolled Platform SRK (psrkAttrs; go-xkms never
// seals under the Shared SRK) and, when platformPolicy is set, binds the
// sealed object itself to the configured platform PCR
// (types.KeyAttributes.PlatformPolicy) -- independent of any per-call
// options. This adapter exists because pkg/storage/sealed.Backend -- the
// generic wrapper the platform store's sealed.New composes -- always calls
// Unseal with nil *types.UnsealOptions, so neither the parent nor the
// PlatformPolicy flag can be threaded through a caller-supplied
// opts.KeyAttributes on the unseal side; this type supplies both
// consistently on both the seal and the unseal path instead.
type platformPolicySealer struct {
	inner          types.Sealer
	cn             string
	psrkAttrs      *types.KeyAttributes
	platformPolicy bool
}

// Compile-time interface check.
var _ types.Sealer = (*platformPolicySealer)(nil)

// CanSeal delegates to the wrapped sealer.
func (p *platformPolicySealer) CanSeal() bool {
	return p.inner.CanSeal()
}

// keyAttrs builds a fresh KeyAttributes identifying the sealed object, always
// parented to the enrolled Platform SRK. A fresh value is built per call
// because the underlying TPM library mutates a sealed object's own
// KeyAttributes in place (SealData, TPMAttributes.Name/Handle) as a side
// effect of Seal/Unseal, and reusing one across calls would leak state from
// the previous call into the next.
func (p *platformPolicySealer) keyAttrs() *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:             p.cn,
		Parent:         p.psrkAttrs,
		PlatformPolicy: p.platformPolicy,
	}
}

// Seal seals data under the Platform SRK, ignoring any KeyAttributes the
// caller supplied in opts (the platform store's sealer always owns key
// identity for its own strategy).
func (p *platformPolicySealer) Seal(ctx context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return p.inner.Seal(ctx, data, &types.SealOptions{KeyAttributes: p.keyAttrs()})
}

// Unseal unseals data under the Platform SRK, ignoring any (always-nil, from
// sealed.Backend) caller-supplied opts. Authorizing the Platform SRK itself
// requires a live-PCR PolicyPCR session (no PIN is presented here), so a
// platform state that no longer matches what the Platform SRK -- or, when
// platformPolicy is set, the sealed object itself -- was authorized under
// fails TPM2_PolicyPCR, and this call surfaces that as an unseal error.
func (p *platformPolicySealer) Unseal(ctx context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return p.inner.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: p.keyAttrs()})
}

// fixedKeyAttrsSealer wraps a types.Sealer so every Seal/Unseal call carries
// the same KeyAttributes, regardless of caller-supplied opts. The
// PKCS#11/cloud-KMS-shaped backends require opts.KeyAttributes on both Seal
// and Unseal to identify their symmetric wrapping key, but
// pkg/storage/sealed.Backend -- the generic wrapper the platform store's
// sealed.New composes -- always calls Unseal with nil options, so a backend
// with this requirement cannot get them from the caller on the unseal side.
// Used by the awskms/gcpkms/azurekv platform-store sealers.
type fixedKeyAttrsSealer struct {
	inner types.Sealer
	attrs *types.KeyAttributes
}

// Compile-time interface check.
var _ types.Sealer = (*fixedKeyAttrsSealer)(nil)

// CanSeal delegates to the wrapped sealer.
func (f *fixedKeyAttrsSealer) CanSeal() bool {
	return f.inner.CanSeal()
}

// Seal seals data using the fixed key identity, ignoring any KeyAttributes
// the caller supplied in opts.
func (f *fixedKeyAttrsSealer) Seal(ctx context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return f.inner.Seal(ctx, data, &types.SealOptions{KeyAttributes: f.attrs})
}

// Unseal unseals data using the fixed key identity, ignoring any
// (always-nil, from sealed.Backend) caller-supplied opts.
func (f *fixedKeyAttrsSealer) Unseal(ctx context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return f.inner.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: f.attrs})
}
