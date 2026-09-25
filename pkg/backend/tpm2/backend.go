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

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend implements types.KeyProvider for TPM 2.0 hardware security modules.
// It wraps the low-level pkg/tpm2 library to provide a unified Backend interface.
type Backend struct {
	config      *Config
	tpm         pkgtpm2.TrustedPlatformModule
	keyBackend  store.KeyBackend
	keyDir      string // directory holding key blobs; used by ListKeys for enumeration
	logger      *slog.Logger
	srkAttrs    *types.KeyAttributes
	tracker     types.AEADSafetyTracker
	mu          sync.RWMutex
	closed      bool
	externalTPM bool // If true, TPM was provided externally and should not be closed
}

// ExternalTPMConfig holds configuration for creating a backend with an external TPM.
type ExternalTPMConfig struct {
	// TPM is the existing TPM instance to use
	TPM pkgtpm2.TrustedPlatformModule

	// KeyBackend is the storage backend for TPM key blobs
	KeyBackend store.KeyBackend

	// KeyDir is the directory where the KeyBackend persists key blobs. It is
	// optional; when set, ListKeys can enumerate keys for this backend. When
	// empty, ListKeys returns no keys (enumeration is unavailable) rather than
	// failing — the store.KeyBackend interface itself exposes no List operation.
	KeyDir string

	// Logger is the logger instance to use (optional)
	Logger *slog.Logger

	// Tracker is the AEAD safety tracker (optional)
	Tracker types.AEADSafetyTracker
}

// NewFileKeyBackend builds the file-backed store.KeyBackend NewBackend
// constructs internally from Config.KeyDir, for callers of
// NewBackendWithTPM: a caller sharing an already-open TPM connection (e.g.
// pkg/server reusing the node-seal flip's or the platform store's single
// open) still needs a real KeyBackend for the wrapper it builds over that
// connection, and this is the one NewBackend itself uses, not a second
// implementation of the same three steps.
func NewFileKeyBackend(logger *slog.Logger, keyDir string) (store.KeyBackend, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create key directory", Err: err}
	}
	fsBackend, err := file.New(keyDir)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create storage backend", Err: err}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return store.NewFileBackend(logger, fsBackend), nil
}

// NewBackendWithTPM creates a new TPM2 backend using an existing TPM instance.
// This is useful when the TPM has already been initialized and provisioned by
// another component (e.g., go-trusted-platform's app.TPM).
//
// The caller is responsible for managing the TPM lifecycle (closing it when done).
// The backend will not close the TPM when Backend.Close() is called.
func NewBackendWithTPM(config *ExternalTPMConfig) (*Backend, error) {
	if config == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "config is nil"}
	}
	if config.TPM == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "TPM is nil"}
	}
	if config.KeyBackend == nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "KeyBackend is nil"}
	}

	// Create logger if not provided
	log := config.Logger
	if log == nil {
		log = slog.Default()
	}

	// Initialize AEAD tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Get the storage parent attributes for key creation. This backend seals
	// and signs for xkms's own purposes, so it always uses the Platform SRK,
	// never the TCG-standard Shared SRK: see resolveSRKAttributes.
	srkAttrs, err := resolveSRKAttributes(config.TPM)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get SRK attributes", Err: err}
	}

	return &Backend{
		config:      nil, // No config when using external TPM
		tpm:         config.TPM,
		keyBackend:  config.KeyBackend,
		keyDir:      config.KeyDir, // optional; enables ListKeys enumeration
		logger:      log,
		srkAttrs:    srkAttrs,
		tracker:     tracker,
		externalTPM: true, // Mark as external so Close() doesn't close the TPM
	}, nil
}

// NewBackend creates a new TPM2 backend instance.
// The backend is initialized and ready for use upon return.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: fmt.Sprintf("%v", err)}
	}

	// Create logger if not provided
	log := config.Logger
	if log == nil {
		log = slog.Default()
	}

	// Initialize AEAD tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	// Create file-based key backend for storing TPM key blobs
	keyBackend, err := NewFileKeyBackend(log, config.KeyDir)
	if err != nil {
		return nil, err
	}

	// Create TPM2 configuration
	tpmConfig := config.ToTPMConfig()

	// Create TPM2 instance
	tpm, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Config:  tpmConfig,
		Backend: keyBackend,
		Logger:  log,
		Tracker: tracker,
	})
	if err != nil {
		// First-boot simulator path: NewTPM2 returns a non-nil tpm with
		// ErrNotInitialized when the simulator opens successfully but the
		// endorsement key is not found. An uninitialized simulator is by
		// definition a fresh dev/test device, so provision EK+SRK in place
		// (mirrors the seal first-boot recipe in go-quicbaas). Real hardware
		// is NEVER auto-provisioned — boot-time provisioning of physical TPMs
		// is an operator action (`xkmsd init`).
		if errors.Is(err, pkgtpm2.ErrNotInitialized) && config.UseSimulator && tpm != nil {
			if perr := provisionSimulatorEKSRK(tpm, tpmConfig); perr != nil {
				closeErr := tpm.Close()
				return nil, &errs.Joined{Lead: ErrNotInitialized, Detail: "simulator provisioning failed", Cause: errors.Join(perr, closeErr)}
			}
		} else {
			// Close the TPM if it was partially initialized. Without closing,
			// the simulator's global mutex is never released, causing
			// deadlocks in subsequent calls.
			var closeErr error
			if tpm != nil {
				closeErr = tpm.Close()
			}
			// Check for initialization error - TPM may need provisioning
			if errors.Is(err, pkgtpm2.ErrNotInitialized) {
				return nil, errors.Join(&errs.Detail{Err: ErrNotInitialized, Detail: "TPM needs provisioning"}, closeErr)
			}
			return nil, &errs.Wrapped{Msg: "failed to initialize TPM", Err: errors.Join(err, closeErr)}
		}
	}

	// Get the storage parent attributes for key creation (see
	// resolveSRKAttributes for why this backend always uses the Platform SRK).
	srkAttrs, err := resolveSRKAttributes(tpm)
	if err != nil {
		closeErr := tpm.Close()
		return nil, &errs.Wrapped{Msg: "failed to get SRK attributes", Err: errors.Join(err, closeErr)}
	}

	return &Backend{
		config:     config,
		tpm:        tpm,
		keyBackend: keyBackend,
		keyDir:     config.KeyDir,
		logger:     log,
		srkAttrs:   srkAttrs,
		tracker:    tracker,
	}, nil
}

// resolveSRKAttributes returns the storage parent this backend uses for its
// own key operations: the Platform SRK, always. This backend never uses the
// TCG-standard Shared SRK -- it exists so other TCG-aware software sharing
// the TPM finds it in its well-known, default state, not so xkms can borrow
// it as a storage parent. A TPM opened by another component (e.g.
// go-trusted-platform's app.TPM) that provisioned the SSRK but was never
// enrolled through PlatformKeyStore.Initialize/EnrollPlatformSRK has no
// Platform SRK yet, and construction fails rather than silently falling back
// to the SSRK. This mirrors TPM2.defaultSealKeyAttributes in pkg/tpm2, so a
// backend built here and a direct pkg/tpm2 Sealer resolve to the same parent
// given the same TPM.
func resolveSRKAttributes(tpm pkgtpm2.TrustedPlatformModule) (*types.KeyAttributes, error) {
	srkAttrs, err := tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "Platform SRK unavailable", Err: err}
	}
	return srkAttrs, nil
}

// provisionSimulatorEKSRK provisions the endorsement key, the TCG-standard
// Shared SRK and the Platform SRK on a freshly-reset TPM simulator. It
// mirrors the proven first-boot recipe used by the sshbackend/fido2
// integration suites and the go-quicbaas seal factory: EKAttributesFromConfig
// → CreateEK → SRKAttributesFromConfig (parented to the EK) → CreateSRK for
// the SSRK, then PlatformSRKAttributesFromConfig → CreateSRK for the Platform
// SRK this backend actually uses (see NewBackend). Callers must only invoke
// this for simulator-backed configs; physical TPMs are provisioned by an
// operator.
//
// The simulator is freshly reset, so the Owner hierarchy carries empty auth
// at this point regardless of what either SRK config declares -- neither
// SRKAttributesFromConfig nor PlatformSRKAttributesFromConfig is asked to
// authorize anything else here.
func provisionSimulatorEKSRK(tpm pkgtpm2.TrustedPlatformModule, cfg *pkgtpm2.Config) error {
	if cfg.EK == nil || cfg.SSRK == nil || cfg.PlatformSRK == nil {
		return &errs.Detail{Err: ErrInvalidConfig, Detail: "simulator provisioning requires EK, SSRK and PlatformSRK configs"}
	}
	ekAttrs, err := pkgtpm2.EKAttributesFromConfig(*cfg.EK, nil, nil)
	if err != nil {
		return &errs.Wrapped{Msg: "EK attributes", Err: err}
	}
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return &errs.Wrapped{Msg: "create EK", Err: err}
	}

	// The TCG-standard Shared SRK, provisioned per spec even though this
	// backend does not use it for its own key operations: other TCG-aware
	// software sharing this TPM expects it at its well-known handle.
	ssrkAttrs, err := pkgtpm2.SRKAttributesFromConfig(*cfg.SSRK)
	if err != nil {
		return &errs.Wrapped{Msg: "SSRK attributes", Err: err}
	}
	ssrkAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(ssrkAttrs); err != nil {
		return &errs.Wrapped{Msg: "create SSRK", Err: err}
	}

	// The Platform SRK is this backend's own storage parent (see NewBackend).
	platformSRKAttrs, err := pkgtpm2.PlatformSRKAttributesFromConfig(cfg)
	if err != nil {
		return &errs.Wrapped{Msg: "Platform SRK attributes", Err: err}
	}
	platformSRKAttrs.Parent = ekAttrs
	if err := tpm.CreateSRK(platformSRKAttrs); err != nil {
		return &errs.Wrapped{Msg: "create Platform SRK", Err: err}
	}

	return nil
}

// Type returns the backend type (TPM2).
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeTPM2
}

// Capabilities returns the capabilities of this backend.
// TPM2 is a hardware-backed security module.
// SecurityLevel is VeryHigh - keys are hardware-bound and non-exportable.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true // TPM supports sealing/unsealing
	caps.Sealing = true             // TPM supports seal/unseal operations
	caps.Attestation = true         // TPM supports key attestation via TPM2_Certify
	caps.SecurityLevel = types.SecurityLevelVeryHigh
	return caps
}

// GenerateKey generates a new key in the TPM with the given attributes.
// The private key never leaves the TPM hardware.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Set store type
	attrs.StoreType = types.StoreTPM2

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		pub, err := b.tpm.CreateRSA(attrs, b.keyBackend, false)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create RSA key", Err: err}
		}
		// Return a TPM signer that wraps the key
		return &tpm2Signer{
			backend:   b,
			attrs:     attrs,
			publicKey: pub,
		}, nil

	case x509.ECDSA:
		// Set default curve if not specified
		if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: elliptic.P256(),
			}
		}
		pub, err := b.tpm.CreateECDSA(attrs, b.keyBackend, false)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create ECDSA key", Err: err}
		}
		// Return a TPM signer that wraps the key
		return &tpm2Signer{
			backend:   b,
			attrs:     attrs,
			publicKey: pub,
		}, nil

	default:
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}
}

// GetKey retrieves an existing key from the TPM by its attributes.
// Returns a crypto.Signer that performs operations using the TPM.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Set store type
	attrs.StoreType = types.StoreTPM2

	// Try to load the key from the backend to verify it exists. Only a
	// genuine "no such object" result from the underlying store (which
	// surfaces as storage.ErrNotFound through keyBackend.Get) is reported
	// as ErrKeyNotFound. Any other failure -- a permission error, a
	// transient I/O fault, a corrupt or partially written blob -- must not
	// be conflated with "key does not exist yet", since callers such as
	// getOrGenerateCAKey use that distinction to decide whether it is safe
	// to generate a replacement key.
	_, err := b.keyBackend.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: ErrKeyNotFound, Detail: attrs.CN}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// Get the public blob to determine key type
	pubData, err := b.keyBackend.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: ErrKeyNotFound, Detail: attrs.CN}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// Parse the public key to determine algorithm
	pubKey, err := b.parsePublicKey(pubData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return &tpm2Signer{
		backend:   b,
		attrs:     attrs,
		publicKey: pubKey,
	}, nil
}

// DeleteKey removes a key from the TPM and its associated storage.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrNotInitialized
	}

	if attrs == nil {
		return ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	// Delete the key using TPM2 library
	if err := b.tpm.DeleteKey(attrs, b.keyBackend); err != nil {
		return &errs.Wrapped{Msg: "failed to delete key", Err: err}
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	// List files in the key directory with .blob extension (private blobs).
	// Prefer the keyDir field (set by both constructors); fall back to the
	// config for backends built directly with a Config. When a backend is
	// created with an external TPM and no KeyDir, enumeration is unavailable
	// (the KeyBackend interface exposes no List operation), so report no keys
	// rather than dereferencing a nil config.
	keyDir := b.keyDir
	if keyDir == "" && b.config != nil {
		keyDir = b.config.KeyDir
	}
	if keyDir == "" {
		return []*types.KeyAttributes{}, nil
	}
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.KeyAttributes{}, nil
		}
		return nil, &errs.Wrapped{Msg: "failed to list key directory", Err: err}
	}

	var keys []*types.KeyAttributes
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Look for private blob files
		if ext := filepath.Ext(name); ext == store.FSEXT_PRIVATE_BLOB {
			cn := name[:len(name)-len(ext)]
			attrs := &types.KeyAttributes{
				CN:        cn,
				StoreType: types.StoreTPM2,
			}
			// Recover the key algorithm from the persisted public blob so that
			// downstream consumers (e.g. DeleteKey, which branches on
			// KeyAlgorithm to choose the load-vs-unseal delete path) operate on
			// the correct key type. This is best-effort: a missing or malformed
			// public blob, or a sealed/keyedhash object, leaves KeyAlgorithm
			// unset and must not fail enumeration.
			if algo, ok := b.keyAlgorithmFromPublicBlob(cn); ok {
				attrs.KeyAlgorithm = algo
			}
			// Recover the PIV slot from the "piv-<slot>" CN convention.
			if strings.HasPrefix(cn, pivCNPrefix) {
				attrs.PIVSlot = cn[len(pivCNPrefix):]
			}
			keys = append(keys, attrs)
		}
	}

	return keys, nil
}

// pivCNPrefix is the common-name prefix used for TPM2-backed PIV keys. The
// slot identifier (e.g. "9a") follows the prefix in the CN ("piv-9a").
const pivCNPrefix = "piv-"

// keyAlgorithmFromPublicBlob recovers the X.509 public-key algorithm of a
// persisted key by unmarshaling its stored TPM2B_PUBLIC blob
// (store.FSEXT_PUBLIC_BLOB). It is best-effort: any failure, or a non-asymmetric
// object such as a sealed/keyedhash key, returns (UnknownPublicKeyAlgorithm,
// false) so that callers fall back to their existing behavior without erroring.
func (b *Backend) keyAlgorithmFromPublicBlob(cn string) (x509.PublicKeyAlgorithm, bool) {
	if b.keyBackend == nil {
		return x509.UnknownPublicKeyAlgorithm, false
	}

	pubBytes, err := b.keyBackend.Get(&types.KeyAttributes{CN: cn}, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm, false
	}

	// The stored public blob is the bare TPMTPublic marshaling produced by
	// outPublic.Bytes() (no length prefix), so it must be wrapped with
	// BytesAs2B, mirroring the production read path in TPM2.ParsePublicKey.
	pub2b := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)
	pub, err := pub2b.Contents()
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm, false
	}

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		return x509.RSA, true
	case tpm2.TPMAlgECC:
		return x509.ECDSA, true
	default:
		return x509.UnknownPublicKeyAlgorithm, false
	}
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: "key does not implement crypto.Signer"}
	}
	return signer, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// Note: Decryption requires the key to be created with encryption capability.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, &errs.Detail{Err: ErrDecryptionNotSupported, Detail: "key does not implement crypto.Decrypter"}
	}
	return decrypter, nil
}

// RotateKey is not supported for TPM2 keys as they are hardware-backed.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return ErrKeyRotationNotSupported
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Don't close the TPM if it was provided externally
	// The caller is responsible for managing its lifecycle
	if b.tpm != nil && !b.externalTPM {
		if err := b.tpm.Close(); err != nil {
			return &errs.Wrapped{Msg: "failed to close TPM", Err: err}
		}
	}

	return nil
}

// TPM returns the underlying TPM2 instance for advanced operations.
// TPM returns the underlying TrustedPlatformModule instance.
func (b *Backend) TPM() pkgtpm2.TrustedPlatformModule {
	return b.tpm
}

// SetTPM replaces the underlying TPM instance. This allows sharing a single
// TPM connection (and its PlatformKeyStore, config, policy state) across
// multiple backends that access the same physical TPM. The old TPM is NOT
// closed — the caller is responsible for its lifecycle.
func (b *Backend) SetTPM(tpm pkgtpm2.TrustedPlatformModule) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.externalTPM = true // don't close on shutdown — caller owns it
	b.tpm = tpm
}

// KeyBackend returns the underlying key storage backend.
func (b *Backend) KeyBackend() store.KeyBackend {
	return b.keyBackend
}

// SRKAttributes returns the Storage Root Key attributes.
func (b *Backend) SRKAttributes() *types.KeyAttributes {
	return b.srkAttrs
}

// parsePublicKey parses a TPM2B_PUBLIC blob and returns the crypto.PublicKey
func (b *Backend) parsePublicKey(pubData []byte) (crypto.PublicKey, error) {
	return b.tpm.ParsePublicKey(pubData)
}

// tpm2Signer implements crypto.Signer using the TPM
type tpm2Signer struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// Public returns the public key corresponding to the opaque private key.
func (s *tpm2Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key using the TPM.
func (s *tpm2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	if s.backend.closed {
		return nil, ErrNotInitialized
	}

	// Create TPM signer opts
	signerOpts := &store.SignerOpts{
		KeyAttributes: s.attrs,
		Backend:       s.backend.keyBackend,
	}

	// If opts contains hash info, use it
	if opts != nil {
		s.attrs.Hash = opts.HashFunc()
	}

	// Sign using TPM
	signature, err := s.backend.tpm.Sign(rand, digest, signerOpts)
	if err != nil {
		// A TPM that cannot perform the requested operation at all is a
		// capability boundary, not a device fault, and callers have to be able
		// to tell the two apart -- "this token cannot do raw RSA" is actionable
		// (retry naming a digest, or use another backend) where "something
		// broke" is not. Joining ErrUnsupportedOperation puts the refusal on the
		// backend's own capability sentinel so every layer above classifies it
		// the same way it classifies any other unsupported operation.
		//
		// ErrSignSchemeMismatch belongs in the same class: a key created with a
		// fixed scheme genuinely cannot sign under another digest, so the
		// request is unsupported for that key rather than broken. Keys created
		// before this package moved to TPM_ALG_NULL templates are the ones that
		// produce it, and an application that meets it should either name the
		// digest the key was created with or rotate to a new key.
		if errors.Is(err, pkgtpm2.ErrRawRSASignUnsupported) ||
			errors.Is(err, pkgtpm2.ErrSchemeHashUnresolved) ||
			errors.Is(err, pkgtpm2.ErrSignSchemeMismatch) {

			return nil, errors.Join(ErrUnsupportedOperation, err)
		}
		return nil, &errs.Wrapped{Msg: "TPM sign failed", Err: err}
	}

	return signature, nil
}

// tpm2Decrypter implements crypto.Decrypter using the TPM
type tpm2Decrypter struct {
	*tpm2Signer
}

// Decrypt decrypts ciphertext with the private key using the TPM.
func (d *tpm2Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.backend.mu.RLock()
	defer d.backend.mu.RUnlock()

	if d.backend.closed {
		return nil, ErrNotInitialized
	}

	// For RSA keys, use TPM's RSADecrypt
	if d.attrs.KeyAlgorithm == x509.RSA {
		// Load the key first to get the handle
		loadResp, err := d.backend.tpm.LoadKeyPair(d.attrs, nil, d.backend.keyBackend)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to load key", Err: err}
		}
		defer d.backend.tpm.Flush(loadResp.ObjectHandle)

		// Read the public to get the name
		pub, err := tpm2.ReadPublic{
			ObjectHandle: loadResp.ObjectHandle,
		}.Execute(d.backend.tpm.Transport())
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to read public", Err: err}
		}

		// Decrypt
		plaintext, err := d.backend.tpm.RSADecrypt(loadResp.ObjectHandle, pub.Name, ciphertext)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "TPM decrypt failed", Err: err}
		}
		return plaintext, nil
	}

	return nil, &errs.Detail{Err: ErrDecryptionNotSupported, Detail: "only RSA decryption is supported"}
}

// =============================================================================
// KeyAgreementBackend Implementation
// =============================================================================

// DeriveKeyECDH performs ECDH key agreement using the TPM and derives a symmetric key.
//
// This implements the types.KeyAgreementProvider interface for TPM2.
// The operation:
//  1. Loads the private key identified by privateKeyAttrs into the TPM
//  2. Parses the peer's public key from peerPublicKey bytes
//  3. Executes TPM2_ECDH_ZGen to compute the raw shared secret
//  4. Applies the KDF specified in kdfParams to derive the final key
//
// The peer public key must be in one of the following formats:
//   - DER-encoded SubjectPublicKeyInfo (SPKI)
//   - SEC1 uncompressed point format (0x04 || X || Y)
//
// Per TCG TPM 2.0 specification Part 3, section 14.5, the TPM2_ECDH_ZGen
// command computes Z = [privateKey]Q where Q is the peer's public key point.
// The shared secret is the X coordinate of Z (per NIST SP 800-56A).
func (b *Backend) DeriveKeyECDH(ctx context.Context, privateKeyAttrs *types.KeyAttributes, peerPublicKey []byte, kdfParams *types.KDFParams) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if privateKeyAttrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	if len(peerPublicKey) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "peer public key is empty"}
	}

	if kdfParams == nil {
		kdfParams = types.DefaultKDFParams()
	}

	// Validate KDF params
	if err := kdfParams.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid KDF parameters", Err: err}
	}

	// Set parent to SRK if not specified
	if privateKeyAttrs.Parent == nil {
		privateKeyAttrs.Parent = b.srkAttrs
	}

	// Set store type
	privateKeyAttrs.StoreType = types.StoreTPM2

	// Parse the peer's public key to extract the curve and point coordinates
	eccPoint, curve, err := b.parsePeerPublicKey(peerPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse peer public key", Err: err}
	}

	// Verify the curve matches the private key's curve (if specified)
	if privateKeyAttrs.ECCAttributes != nil && privateKeyAttrs.ECCAttributes.Curve != nil {
		if privateKeyAttrs.ECCAttributes.Curve.Params().Name != curve.Params().Name {
			return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("private key curve %s does not match peer public key curve %s", privateKeyAttrs.ECCAttributes.Curve.Params().Name, curve.Params().Name)}
		}
	}

	// Perform ECDH key agreement using TPM2_ECDH_ZGen
	sharedSecret, err := b.tpm.ECDHZGen(privateKeyAttrs, eccPoint, b.keyBackend)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "ECDH key agreement failed", Err: err}
	}

	// Apply KDF to derive the final key
	derivedKey, err := b.applyKDF(sharedSecret, kdfParams)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KDF failed", Err: err}
	}

	return derivedKey, nil
}

// SupportedCurves returns the list of elliptic curves supported by the TPM for key agreement.
// TPM 2.0 typically supports NIST P-256, P-384, and P-521 curves.
func (b *Backend) SupportedCurves() []string {
	// TPM 2.0 mandatory curves per TCG specification
	// P-256 is required, P-384 and P-521 are optional but commonly supported
	return []string{
		"P-256", // NIST P-256 / secp256r1 (mandatory)
		"P-384", // NIST P-384 / secp384r1 (common)
		"P-521", // NIST P-521 / secp521r1 (common)
	}
}

// parsePeerPublicKey parses a peer's public key from DER or SEC1 format.
// Returns the TPM ECC point representation and the curve.
func (b *Backend) parsePeerPublicKey(peerPublicKey []byte) (*tpm2.TPMSECCPoint, elliptic.Curve, error) {
	// First, try parsing as DER-encoded SubjectPublicKeyInfo (SPKI)
	pub, err := x509.ParsePKIXPublicKey(peerPublicKey)
	if err == nil {
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("expected ECDSA public key, got %T", pub)}
		}
		return &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: ecdsaPub.X.Bytes()}, //nolint:staticcheck // TPM2 wire format requires raw EC coordinates
			Y: tpm2.TPM2BECCParameter{Buffer: ecdsaPub.Y.Bytes()}, //nolint:staticcheck // TPM2 wire format requires raw EC coordinates
		}, ecdsaPub.Curve, nil
	}

	// Try parsing as SEC1 uncompressed point format (0x04 || X || Y)
	if len(peerPublicKey) > 1 && peerPublicKey[0] == 0x04 {
		// Determine curve from key length
		// P-256: 65 bytes (1 + 32 + 32)
		// P-384: 97 bytes (1 + 48 + 48)
		// P-521: 133 bytes (1 + 66 + 66)
		pointLen := len(peerPublicKey) - 1
		var curve elliptic.Curve
		var coordLen int

		switch pointLen {
		case 64: // P-256
			curve = elliptic.P256()
			coordLen = 32
		case 96: // P-384
			curve = elliptic.P384()
			coordLen = 48
		case 132: // P-521
			curve = elliptic.P521()
			coordLen = 66
		default:
			return nil, nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unsupported SEC1 point length %d", pointLen)}
		}

		x := peerPublicKey[1 : 1+coordLen]
		y := peerPublicKey[1+coordLen:]

		return &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}, curve, nil
	}

	return nil, nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: "unable to parse public key (not DER or SEC1 format)"}
}

// applyKDF derives a key from an ECDH shared secret using the canonical KDF
// implementation in pkg/crypto/kdf, reached through types.KDFParams.Derive.
// Every backend derives through that one entry point, so the same parameters
// yield the same bytes here as on the software, PKCS#11, and phone backends.
func (b *Backend) applyKDF(sharedSecret []byte, params *types.KDFParams) ([]byte, error) {
	if params == nil {
		return nil, ErrInvalidKDFParams
	}
	return params.Derive(sharedSecret)
}

// GenerateSymmetricKey generates a new symmetric key in the TPM.
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	// Set parent to SRK if not specified
	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	attrs.StoreType = types.StoreTPM2

	return b.tpm.GenerateSymmetricKey(attrs)
}

// GetSymmetricKey retrieves an existing symmetric key from the TPM.
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	attrs.StoreType = types.StoreTPM2

	return b.tpm.GetSymmetricKey(attrs)
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key identified by attrs.
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}

	attrs.StoreType = types.StoreTPM2

	return b.tpm.SymmetricEncrypter(attrs)
}

// GetTracker returns the AEAD safety tracker for this backend.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// Ensure interfaces are implemented at compile time
var _ types.KeyProvider = (*Backend)(nil)
var _ types.AttestingKeyProvider = (*Backend)(nil)
var _ types.KeyAgreementProvider = (*Backend)(nil)
var _ types.SymmetricKeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
var _ crypto.Signer = (*tpm2Signer)(nil)
var _ crypto.Decrypter = (*tpm2Decrypter)(nil)
