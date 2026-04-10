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

// Package credentials manages sealed backend credentials using configurable
// seal strategies. It wraps seal.PlatformStore and seal.Barrier to seal/unseal
// credentials to any backend (barrier, TPM2, PKCS#11, cloud KMS, software, or
// manual entry).
package credentials

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// StrategyManual is the strategy ID for manual credential entry.
const StrategyManual = "manual"

// credentialPrefix namespaces credential keys within the storage backend.
const credentialPrefix = "credentials/"

// validStrategies maps all supported strategy names to true for O(1) validation.
var validStrategies = map[string]bool{
	StrategyManual: true,
	"barrier":      true,
	"tpm2":         true,
	"pkcs11":       true,
	"aws_kms":      true,
	"gcp_kms":      true,
	"azure_kv":     true,
	"vault":        true,
	"software":     true,
}

// Config holds credential service configuration.
type Config struct {
	// Strategy determines how backend credentials are sealed at rest.
	// Valid values: "manual", "barrier", "tpm2", "pkcs11", "aws_kms",
	// "gcp_kms", "azure_kv", "vault", "software"
	// Default: "manual" -- operator enters credentials at each startup.
	Strategy string
}

// Service manages sealed backend credentials using configurable seal strategies.
// It wraps seal.PlatformStore to seal/unseal credentials to any backend
// (barrier, TPM2, PKCS#11, cloud KMS, software, or manual entry).
type Service struct {
	platformStore seal.PlatformStore
	barrier       *seal.Barrier
	strategy      string
	logger        *slog.Logger

	// manualCreds stores credentials submitted by operator in manual mode.
	// Protected by mu.
	mu          sync.RWMutex
	manualCreds map[string][]byte

	// waiters tracks channels waiting for manual credential submission.
	waitersMu sync.Mutex
	waiters   map[string][]chan []byte
}

// New creates a new credential Service. For "manual" strategy, only logger is
// required. For "barrier" strategy, the barrier must be provided. For other
// strategies, platformStore must be provided.
func New(cfg *Config, platformStore seal.PlatformStore, barrier *seal.Barrier, logger *slog.Logger) (*Service, error) {
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = StrategyManual
	}

	if !validStrategies[strategy] {
		return nil, ErrInvalidStrategy
	}

	if strategy == "barrier" && barrier == nil {
		return nil, ErrNilBarrier
	}

	if isPlatformStrategy(strategy) && platformStore == nil {
		return nil, ErrNilPlatformStore
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		platformStore: platformStore,
		barrier:       barrier,
		strategy:      strategy,
		logger:        logger.With("component", "credential_service"),
		manualCreds:   make(map[string][]byte),
		waiters:       make(map[string][]chan []byte),
	}, nil
}

// StoreCredential seals a named credential using the configured strategy.
// For "manual" strategy, this stores in memory (for operator-submitted creds).
// For "barrier" strategy, stores inside the barrier.
// For other strategies, delegates to PlatformStore.
func (s *Service) StoreCredential(ctx context.Context, name string, value []byte) error {
	if err := validateInput(name, value); err != nil {
		return err
	}

	switch s.strategy {
	case StrategyManual:
		return s.storeManual(name, value)
	case "barrier":
		return s.storeBarrier(name, value)
	default:
		return s.storePlatform(ctx, name, value)
	}
}

// RetrieveCredential unseals a named credential.
// For "manual" strategy: returns immediately if already submitted, or blocks
// until submitted via SubmitCredential or context is cancelled.
// For "barrier" strategy: reads from barrier.
// For other strategies: reads from PlatformStore.
func (s *Service) RetrieveCredential(ctx context.Context, name string) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrEmptyCredentialName
	}

	switch s.strategy {
	case StrategyManual:
		return s.retrieveManual(ctx, name)
	case "barrier":
		return s.retrieveBarrier(name)
	default:
		return s.retrievePlatform(ctx, name)
	}
}

// SubmitCredential is used by operators to submit a credential in "manual" mode.
// The value is stored in memory and any blocked RetrieveCredential calls are
// unblocked. For non-manual strategies, this delegates to StoreCredential.
func (s *Service) SubmitCredential(ctx context.Context, name string, value []byte) error {
	if err := validateInput(name, value); err != nil {
		return err
	}

	if s.strategy != StrategyManual {
		return s.StoreCredential(ctx, name, value)
	}

	s.mu.Lock()
	if _, exists := s.manualCreds[name]; exists {
		s.mu.Unlock()
		return ErrCredentialAlreadySubmitted
	}

	// Copy the value to avoid external mutation.
	cred := make([]byte, len(value))
	copy(cred, value)
	s.manualCreds[name] = cred
	s.mu.Unlock()

	// Notify all blocked waiters.
	s.waitersMu.Lock()
	if waiters, ok := s.waiters[name]; ok {
		for _, ch := range waiters {
			// Send a copy to each waiter.
			waiterCopy := make([]byte, len(cred))
			copy(waiterCopy, cred)
			select {
			case ch <- waiterCopy:
			default:
			}
		}
		delete(s.waiters, name)
	}
	s.waitersMu.Unlock()

	s.logger.Info("manual credential submitted", "name", name)
	return nil
}

// DeleteCredential removes a stored credential.
func (s *Service) DeleteCredential(ctx context.Context, name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrEmptyCredentialName
	}

	switch s.strategy {
	case StrategyManual:
		return s.deleteManual(name)
	case "barrier":
		return s.deleteBarrier(name)
	default:
		return s.deletePlatform(ctx, name)
	}
}

// AutoUnsealAvailable returns true if the configured strategy supports
// auto-unseal (i.e., credentials can be retrieved without operator
// intervention).
func (s *Service) AutoUnsealAvailable() bool {
	return s.strategy != StrategyManual
}

// Strategy returns the configured strategy name.
func (s *Service) Strategy() string {
	return s.strategy
}

// storeManual stores a credential in the in-memory map.
func (s *Service) storeManual(name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred := make([]byte, len(value))
	copy(cred, value)
	s.manualCreds[name] = cred

	s.logger.Debug("credential stored in memory", "name", name)
	return nil
}

// storeBarrier stores a credential via the barrier's Put method.
func (s *Service) storeBarrier(name string, value []byte) error {
	if err := s.barrier.Put(context.Background(), credentialPrefix+name, value); err != nil {
		return err
	}
	s.logger.Debug("credential stored in barrier", "name", name)
	return nil
}

// storePlatform stores a credential via the PlatformStore.
func (s *Service) storePlatform(ctx context.Context, name string, value []byte) error {
	if err := s.platformStore.Put(ctx, credentialPrefix+name, value); err != nil {
		return err
	}
	s.logger.Debug("credential stored in platform store", "name", name, "strategy", s.strategy)
	return nil
}

// retrieveManual returns a credential from the in-memory map if present,
// otherwise blocks until the credential is submitted or context is cancelled.
func (s *Service) retrieveManual(ctx context.Context, name string) ([]byte, error) {
	// Check if already submitted.
	s.mu.RLock()
	if cred, exists := s.manualCreds[name]; exists {
		result := make([]byte, len(cred))
		copy(result, cred)
		s.mu.RUnlock()
		return result, nil
	}
	s.mu.RUnlock()

	// Register a waiter channel.
	ch := make(chan []byte, 1)
	s.waitersMu.Lock()
	s.waiters[name] = append(s.waiters[name], ch)
	s.waitersMu.Unlock()

	// Block until credential is submitted or context is done.
	select {
	case value := <-ch:
		return value, nil
	case <-ctx.Done():
		// Clean up the waiter.
		s.waitersMu.Lock()
		waiters := s.waiters[name]
		for i, w := range waiters {
			if w == ch {
				s.waiters[name] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		if len(s.waiters[name]) == 0 {
			delete(s.waiters, name)
		}
		s.waitersMu.Unlock()
		return nil, ctx.Err()
	}
}

// retrieveBarrier reads a credential from the barrier.
func (s *Service) retrieveBarrier(name string) ([]byte, error) {
	value, err := s.barrier.Get(context.Background(), credentialPrefix+name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}
	return value, nil
}

// retrievePlatform reads a credential from the PlatformStore.
func (s *Service) retrievePlatform(ctx context.Context, name string) ([]byte, error) {
	value, err := s.platformStore.Get(ctx, credentialPrefix+name)
	if err != nil {
		if errors.Is(err, seal.ErrSecretNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}
	return value, nil
}

// deleteManual removes a credential from the in-memory map and zeroes its value.
func (s *Service) deleteManual(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, exists := s.manualCreds[name]
	if !exists {
		return ErrCredentialNotFound
	}
	mem.Zero(cred)
	delete(s.manualCreds, name)

	s.logger.Debug("credential deleted from memory", "name", name)
	return nil
}

// deleteBarrier removes a credential from the barrier.
func (s *Service) deleteBarrier(name string) error {
	err := s.barrier.Delete(context.Background(), credentialPrefix+name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrCredentialNotFound
		}
		return err
	}
	s.logger.Debug("credential deleted from barrier", "name", name)
	return nil
}

// deletePlatform removes a credential from the PlatformStore.
func (s *Service) deletePlatform(ctx context.Context, name string) error {
	err := s.platformStore.Delete(ctx, credentialPrefix+name)
	if err != nil {
		if errors.Is(err, seal.ErrSecretNotFound) {
			return ErrCredentialNotFound
		}
		return err
	}
	s.logger.Debug("credential deleted from platform store", "name", name, "strategy", s.strategy)
	return nil
}

// isPlatformStrategy returns true if the strategy uses the PlatformStore
// (not manual and not barrier).
func isPlatformStrategy(strategy string) bool {
	return strategy != StrategyManual && strategy != "barrier"
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
