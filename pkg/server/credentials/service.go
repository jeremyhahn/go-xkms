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

// Package credentials manages sealed backend credentials (PKCS#11 user PIN,
// cloud-KMS secrets, and the like) under a configurable strategy.
//
// The manual and barrier strategies are go-qrdb's versioned credential
// service, used as is. What xkms adds are the hardware platform strategies
// (TPM 2.0, PKCS#11, cloud KMS, Vault, passphrase), which keep credentials in
// the sealed seal.PlatformStore; go-qrdb has no equivalent.
package credentials

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"slices"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// StrategyManual is the strategy ID for operator-submitted credentials.
	StrategyManual = qrdbsdk.CredentialStrategyManual

	// StrategyBarrier is the strategy ID for credentials stored in the barrier.
	StrategyBarrier = qrdbsdk.CredentialStrategyBarrier
)

// credentialPrefix namespaces credential keys within the platform store,
// which holds more than credentials.
const credentialPrefix = "credentials/"

// InNamespace reports whether a platform-store secret name falls inside the
// credential namespace. The platform-secrets API refuses such names
// (go-xkms#1465): a credential's value is write-only, and this service is its
// only reader. The name is cleaned first so a dot-segment spelling of the
// same key ("x/../credentials/db") is caught too.
func InNamespace(name string) bool {
	return strings.HasPrefix(path.Clean("/"+name), "/"+credentialPrefix)
}

// validStrategies maps all supported strategy names to true for O(1) validation.
// The cloud-KMS names match the seal layer's StrategyID constants
// (awskms/gcpkms/azurekv, no underscores); there is no underscored alias.
var validStrategies = map[string]bool{
	StrategyManual:  true,
	StrategyBarrier: true,
	"tpm2":          true,
	"pkcs11":        true,
	// Cloud-KMS names (align with pkg/seal StrategyAWSKMS/GCPKMS/AzureKV).
	"awskms":  true,
	"gcpkms":  true,
	"azurekv": true,
	"vault":   true,
	// "passphrase" is the name for password/software-derived sealing
	// (aligns with the seal layer's StrategyPassphrase and qrdb's naming).
	"passphrase": true,
}

// Config holds credential service configuration.
type Config struct {
	// Strategy determines how backend credentials are sealed at rest.
	// Valid values: "manual", "barrier", "tpm2", "pkcs11", "awskms",
	// "gcpkms", "azurekv", "vault", "passphrase".
	// Default: "manual" -- operator enters credentials at each startup.
	Strategy string
}

// credentialStore is the operation set every strategy provides. go-qrdb's
// *qrdbsdk.VersionedCredentialService satisfies it for manual and barrier;
// platformCredentials satisfies it for the hardware strategies.
type credentialStore interface {
	StoreCredential(ctx context.Context, name string, value []byte) error
	RetrieveCredentialBuffer(ctx context.Context, name string) (*secure.Buffer, error)
	SubmitCredential(ctx context.Context, name string, value []byte) error
	DeleteCredential(ctx context.Context, name string) error
	ListCredentials(ctx context.Context) ([]string, error)
}

// Service manages sealed backend credentials using the configured strategy.
type Service struct {
	store    credentialStore
	strategy string
}

// New creates a credential service for cfg.Strategy (default "manual").
// The barrier strategy requires barrier; the platform strategies require
// platformStore.
func New(cfg *Config, platformStore seal.PlatformStore, barrier *seal.Barrier, logger *slog.Logger) (*Service, error) {
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = StrategyManual
	}

	if !validStrategies[strategy] {
		return nil, ErrInvalidStrategy
	}

	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "credential_service")

	if isPlatformStrategy(strategy) {
		if platformStore == nil {
			return nil, ErrNilPlatformStore
		}
		return &Service{
			store:    &platformCredentials{store: platformStore, strategy: strategy, logger: logger},
			strategy: strategy,
		}, nil
	}

	if strategy == StrategyBarrier && barrier == nil {
		return nil, ErrNilBarrier
	}
	store, err := qrdbsdk.NewVersionedCredentialService(&qrdbsdk.CredentialConfig{Strategy: strategy}, barrier, logger)
	if err != nil {
		return nil, err
	}
	return &Service{store: store, strategy: strategy}, nil
}

// StoreCredential seals a named credential using the configured strategy.
func (s *Service) StoreCredential(ctx context.Context, name string, value []byte) error {
	if err := validateInput(name, value); err != nil {
		return err
	}
	return s.store.StoreCredential(ctx, name, value)
}

// RetrieveCredentialBuffer unseals a named credential into protected memory.
// Under the manual strategy it blocks until the credential is submitted or ctx
// is cancelled. The caller owns the returned buffer and must Destroy it.
func (s *Service) RetrieveCredentialBuffer(ctx context.Context, name string) (*secure.Buffer, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrEmptyCredentialName
	}
	return s.store.RetrieveCredentialBuffer(ctx, name)
}

// SubmitCredential is used by operators to submit a credential. Under the
// manual strategy a credential is submitted once, and a second submission
// returns ErrCredentialAlreadySubmitted; the other strategies store it.
func (s *Service) SubmitCredential(ctx context.Context, name string, value []byte) error {
	if err := validateInput(name, value); err != nil {
		return err
	}
	if s.strategy == StrategyManual {
		names, err := s.store.ListCredentials(ctx)
		if err != nil {
			return err
		}
		if slices.Contains(names, name) {
			return ErrCredentialAlreadySubmitted
		}
	}
	return s.store.SubmitCredential(ctx, name, value)
}

// DeleteCredential removes a stored credential.
func (s *Service) DeleteCredential(ctx context.Context, name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrEmptyCredentialName
	}
	return s.store.DeleteCredential(ctx, name)
}

// ListCredentials returns the names of the stored credentials, sorted.
//
// Names only: a credential's value never leaves the seal boundary through
// this call, and there is no read path that returns one to an operator. The
// question this answers is "which credentials has this server been given?",
// which an operator needs in order to know what is still outstanding before
// a backend can unseal.
func (s *Service) ListCredentials(ctx context.Context) ([]string, error) {
	names, err := s.store.ListCredentials(ctx)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

// AutoUnsealAvailable reports whether credentials can be retrieved without
// operator intervention, which every strategy but manual allows.
func (s *Service) AutoUnsealAvailable() bool {
	return s.strategy != StrategyManual
}

// Strategy returns the configured strategy name.
func (s *Service) Strategy() string {
	return s.strategy
}

// platformCredentials keeps credentials in the hardware-sealed platform
// store, namespaced under credentialPrefix.
type platformCredentials struct {
	store    seal.PlatformStore
	strategy string
	logger   *slog.Logger
}

// StoreCredential seals value into the platform store.
func (p *platformCredentials) StoreCredential(ctx context.Context, name string, value []byte) error {
	if err := p.store.Put(ctx, credentialPrefix+name, value); err != nil {
		return err
	}
	p.logger.Debug("credential stored in platform store", "name", name, "strategy", p.strategy)
	return nil
}

// RetrieveCredentialBuffer unseals a credential from the platform store and
// moves it into protected memory; the plaintext slice is wiped on every path.
func (p *platformCredentials) RetrieveCredentialBuffer(ctx context.Context, name string) (*secure.Buffer, error) {
	value, err := p.store.Get(ctx, credentialPrefix+name)
	if errors.Is(err, seal.ErrSecretNotFound) {
		return nil, ErrCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	return secure.NewBufferFromBytes(value)
}

// SubmitCredential stores the credential; only the manual strategy
// distinguishes submission from storage.
func (p *platformCredentials) SubmitCredential(ctx context.Context, name string, value []byte) error {
	return p.StoreCredential(ctx, name, value)
}

// DeleteCredential removes a credential from the platform store.
func (p *platformCredentials) DeleteCredential(ctx context.Context, name string) error {
	err := p.store.Delete(ctx, credentialPrefix+name)
	if errors.Is(err, seal.ErrSecretNotFound) {
		return ErrCredentialNotFound
	}
	if err != nil {
		return err
	}
	p.logger.Debug("credential deleted from platform store", "name", name, "strategy", p.strategy)
	return nil
}

// ListCredentials returns the credential names held in the platform store.
// Entries outside the credential namespace are not credentials and are
// skipped.
func (p *platformCredentials) ListCredentials(ctx context.Context) ([]string, error) {
	keys, err := p.store.List(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		if name, ok := strings.CutPrefix(key, credentialPrefix); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// isPlatformStrategy reports whether strategy keeps credentials in the
// platform store rather than go-qrdb's credential service.
func isPlatformStrategy(strategy string) bool {
	return strategy != StrategyManual && strategy != StrategyBarrier
}

// validateInput checks that name and value are non-empty.
func validateInput(name string, value []byte) error {
	if strings.TrimSpace(name) == "" {
		return ErrEmptyCredentialName
	}
	if len(value) == 0 {
		return ErrEmptyCredentialValue
	}
	return nil
}
