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

package clusterca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// clusterSeedOID identifies the tpm-kek cluster-seed provisioning material in a
// ProvisionedSecret, so a joining node routes it to the tpm-kek consumer.
// (Private Enterprise arc, go-xkms cluster-ca seed.)
var clusterSeedOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

// clusterSeedLen is the cluster seed length in bytes (256-bit).
const clusterSeedLen = 32

// sealedSeedFile is the node-local file holding the TPM-sealed cluster seed so a
// node recovers it across restarts without re-fetching.
const sealedSeedFile = "cluster-seed.sealed"

// tpm-kek strategy errors.
var (
	// ErrSeedUnavailable is returned when the cluster seed is needed but this
	// node has neither generated it (not the bootstrap node) nor obtained it via
	// the post-enrollment secret fetch yet.
	ErrSeedUnavailable = errors.New("clusterca: cluster CA seed unavailable — join enrollment must fetch it first")

	// ErrNoTPMCredentials is returned when the tpm-kek strategy is used without a
	// TPM sealer / credential activator.
	ErrNoTPMCredentials = errors.New("clusterca: tpm-kek strategy requires a TPM sealer and credential activator")
)

// tpmKEKStrategy wraps the replicated cluster CA key under a KEK derived from a
// cluster seed. The seed is generated once on the bootstrap node, sealed to that
// node's local TPM, and delivered to each joining node via TPM credential
// activation during attested enrollment (so it never transits any channel in the
// clear — only the genuine target TPM can recover it). Every node derives the
// same KEK from the seed and thus can load the KEK-wrapped CA key from the
// replicated store — hardware-rooted, without a shared HSM.
type tpmKEKStrategy struct {
	seed                []byte
	bootstrapKeyStorage storage.Backend
	// deps is retained from BootstrapBackends so SecretProvider and
	// ConsumeEnrollmentSecret (which the enrollment layer calls without deps)
	// can reach the TPM credential activator and node-local data dir.
	deps *StrategyDeps
}

// Name reports the strategy identifier.
func (s *tpmKEKStrategy) Name() KeyStrategyName { return KeyStrategyTPMKEK }

// kekProtection derives the keystore KeyProtection (a passphrase equal to the
// HKDF-derived KEK) from the cluster seed, so the software keystore encrypts the
// CA signing keys under the KEK.
func (s *tpmKEKStrategy) kekProtection() (KeyProtection, error) {
	if len(s.seed) == 0 {
		return KeyProtection{}, ErrSeedUnavailable
	}
	kek := make([]byte, 32)
	r := hkdf.New(sha256.New, s.seed, []byte("go-xkms/cluster-ca"), []byte("kek/v1"))
	if _, err := io.ReadFull(r, kek); err != nil {
		return KeyProtection{}, err
	}
	return KeyProtection{Mode: KeyProtectPassphrase, Passphrase: hex.EncodeToString(kek)}, nil
}

// ensureSeed makes the cluster seed available: from memory, then the TPM-sealed
// node-local cache, then (only on the bootstrap node) by generating and sealing
// a fresh one. A joining node that has none yet returns ErrSeedUnavailable — it
// must first obtain the seed via ConsumeEnrollmentSecret.
func (s *tpmKEKStrategy) ensureSeed(ctx context.Context, deps *StrategyDeps) error {
	if len(s.seed) != 0 {
		return nil
	}
	if deps.TPMSealer == nil {
		return ErrNoTPMCredentials
	}
	if seed, err := s.loadSealedSeed(ctx, deps); err == nil {
		s.seed = seed
		return nil
	}
	if !deps.Bootstrapping {
		return ErrSeedUnavailable
	}
	seed := make([]byte, clusterSeedLen)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := s.storeSealedSeed(ctx, deps, seed); err != nil {
		return err
	}
	s.seed = seed
	deps.logger().Info("generated cluster CA seed and sealed it to the local TPM")
	return nil
}

// sealedSeedPath is the node-local path of the TPM-sealed seed blob.
func (s *tpmKEKStrategy) sealedSeedPath(deps *StrategyDeps) string {
	return filepath.Join(deps.NodeLocalDataDir, sealedSeedFile)
}

// storeSealedSeed seals the seed to the local TPM and writes the sealed blob
// node-local (0600).
func (s *tpmKEKStrategy) storeSealedSeed(ctx context.Context, deps *StrategyDeps, seed []byte) error {
	sealed, err := deps.TPMSealer.Seal(ctx, seed, nil)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(deps.NodeLocalDataDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.sealedSeedPath(deps), blob, 0o600)
}

// loadSealedSeed reads and TPM-unseals the node-local sealed seed blob.
func (s *tpmKEKStrategy) loadSealedSeed(ctx context.Context, deps *StrategyDeps) ([]byte, error) {
	blob, err := os.ReadFile(s.sealedSeedPath(deps))
	if err != nil {
		return nil, err
	}
	var sealed types.SealedData
	if err := json.Unmarshal(blob, &sealed); err != nil {
		return nil, err
	}
	return deps.TPMSealer.Unseal(ctx, &sealed, nil)
}

// BootstrapBackends generates/loads the seed (bootstrap node) and builds the
// node-local software keystore whose password is the seed-derived KEK, so the
// CA keys are KEK-wrapped at rest. Joiners have no seed yet at bootstrap and only
// need a local keystore for their transport key, so a joiner (non-bootstrapping)
// falls back to an unkeyed node-local keystore for that purpose.
func (s *tpmKEKStrategy) BootstrapBackends(ctx context.Context, deps *StrategyDeps) (func(string) (xkms.Backend, error), error) {
	if deps.TPMSealer == nil || deps.Credentials == nil {
		return nil, ErrNoTPMCredentials
	}
	protection := KeyProtection{Mode: KeyProtectNone, AllowInsecure: true}
	if err := s.ensureSeed(ctx, deps); err == nil {
		p, kerr := s.kekProtection()
		if kerr != nil {
			return nil, kerr
		}
		protection = p
	} else if deps.Bootstrapping {
		// The bootstrap node must have a seed to pre-stage the KEK-wrapped CA.
		return nil, err
	}

	set, err := newNodeLocalBackendSet(ctx, &NodeLocalBackendsParams{
		DataDir:     deps.NodeLocalDataDir,
		CAConfig:    deps.CAConfig,
		Protection:  protection,
		HardwareTPM: deps.TPMSealer,
		Logger:      deps.logger(),
	})
	if err != nil {
		return nil, err
	}
	s.bootstrapKeyStorage = set.keyStorage
	s.deps = deps
	return set.resolve, nil
}

// RuntimeBackend derives the KEK from the seed (which the node must already hold
// — the bootstrap node generated it; a joiner obtained it via credential
// activation), promotes any node-local bootstrap key into the replicated store,
// and returns the software keystore over the replicated store keyed by the KEK.
func (s *tpmKEKStrategy) RuntimeBackend(ctx context.Context, deps *StrategyDeps) (xkms.Backend, error) {
	if deps.ReplicatedKeyStorage == nil || deps.ReplicatedCertStorage == nil {
		return nil, ErrStrategyMisconfigured
	}
	s.deps = deps
	if err := s.ensureSeed(ctx, deps); err != nil {
		return nil, err
	}
	protection, err := s.kekProtection()
	if err != nil {
		return nil, err
	}
	if err := injectKeystorePassword(ctx, &protection, deps.CAConfig); err != nil {
		return nil, err
	}
	if s.bootstrapKeyStorage != nil {
		if err := promoteKeyStorage(ctx, s.bootstrapKeyStorage, deps.ReplicatedKeyStorage); err != nil {
			return nil, err
		}
		deps.logger().Info("promoted KEK-wrapped cluster CA key into the replicated store")
	}
	return newSoftwareBackend(deps.ReplicatedKeyStorage, deps.ReplicatedCertStorage)
}

// SecretProvider returns the provider that wraps the cluster seed to an enrolling
// node via TPM credential activation. It is the decoupled seam the enrollment
// secret-delivery service invokes. The provider uses the deps retained from
// BootstrapBackends (the TPM credential activator).
func (s *tpmKEKStrategy) SecretProvider() NodeSecretProvider {
	return &tpmKEKSecretProvider{strategy: s}
}

// ConsumeEnrollmentSecret recovers the cluster seed a joining node fetched after
// enrollment: it activates the TPM credential (only this node's TPM can) to
// recover the seed, seals it node-local for restarts, and caches it so
// RuntimeBackend can derive the KEK. Material with a foreign OID is ignored. It
// uses the deps retained from BootstrapBackends.
func (s *tpmKEKStrategy) ConsumeEnrollmentSecret(ctx context.Context, material *ProvisionedSecret) error {
	if material == nil || !material.OID.Equal(clusterSeedOID) {
		return nil
	}
	if s.deps == nil || s.deps.Credentials == nil || s.deps.TPMSealer == nil {
		return ErrNoTPMCredentials
	}
	var cred wrappedCredential
	if err := json.Unmarshal(material.Data, &cred); err != nil {
		return err
	}
	seed, err := s.deps.Credentials.ActivateCredential(cred.CredentialBlob, cred.EncryptedSecret)
	if err != nil {
		return err
	}
	if len(seed) != clusterSeedLen {
		return errors.New("clusterca: activated cluster seed has unexpected length")
	}
	if err := s.storeSealedSeed(ctx, s.deps, seed); err != nil {
		return err
	}
	s.seed = seed
	s.deps.logger().Info("recovered cluster CA seed via TPM credential activation and sealed it locally")
	return nil
}

// wrappedCredential is the JSON-encoded TPM credential-activation output carried
// in a ProvisionedSecret for the cluster seed.
type wrappedCredential struct {
	CredentialBlob  []byte `json:"credential_blob"`
	EncryptedSecret []byte `json:"encrypted_secret"`
}

// tpmKEKSecretProvider wraps the cluster seed to an enrolling node's TPM.
type tpmKEKSecretProvider struct {
	strategy *tpmKEKStrategy
}

// ProvisionFor wraps the cluster seed to the enrolling node's EK + attestation
// key via MakeCredentialWithExternalEK, so only that node's TPM can recover it.
func (p *tpmKEKSecretProvider) ProvisionFor(ctx context.Context, req *NodeSecretRequest) (*ProvisionedSecret, error) {
	deps := p.strategy.deps
	if deps == nil || deps.Credentials == nil {
		return nil, ErrNoTPMCredentials
	}
	if len(p.strategy.seed) == 0 {
		return nil, ErrSeedUnavailable
	}
	if req == nil || req.EKCertificate == nil || len(req.IAKPublic) == 0 {
		return nil, errors.New("clusterca: node secret request missing EK certificate or IAK public area")
	}
	credBlob, encSecret, _, err := deps.Credentials.MakeCredentialWithExternalEK(
		req.EKCertificate, req.IAKPublic, p.strategy.seed)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(&wrappedCredential{CredentialBlob: credBlob, EncryptedSecret: encSecret})
	if err != nil {
		return nil, err
	}
	return &ProvisionedSecret{OID: clusterSeedOID, Data: data}, nil
}
