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

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// MultiBackendConfig configures a multi-backend SSH agent.
type MultiBackendConfig struct {
	// Backends maps backend names to their KeyBackend implementations.
	// At least one backend is required.
	Backends map[string]KeyBackend

	// DefaultBackend is the name of the default backend.
	// Keys from this backend are displayed without the backend prefix.
	// If empty, the first backend added is used as default.
	DefaultBackend string

	// RequireTouch requires touch confirmation for signing operations.
	RequireTouch bool

	// TouchHandler handles touch confirmation requests (optional).
	TouchHandler TouchHandler

	// Logger is the structured logger (optional).
	Logger *slog.Logger
}

// MultiBackendAgent implements ssh/agent.Agent with support for multiple key backends.
// Keys are identified using the extended key ID format: "backend:type:algo:keyname"
// For simplicity, keys from the default backend can be referenced by just their keyname.
type MultiBackendAgent struct {
	backends       map[string]KeyBackend
	defaultBackend string
	requireTouch   bool
	touchHandler   TouchHandler
	logger         *slog.Logger

	mu       sync.RWMutex
	locked   atomic.Bool
	keyCache map[string]*multiBackendCachedKey // fingerprint -> key info
}

// multiBackendCachedKey stores key information including backend for routing.
type multiBackendCachedKey struct {
	backend   string        // Backend name (e.g., "software", "tpm2")
	keyID     string        // Simple key ID within the backend
	fullKeyID string        // Extended key ID for display (e.g., "tpm2:::my-key")
	keyType   string        // Key algorithm type
	publicKey ssh.PublicKey // Parsed SSH public key
}

// NewMultiBackendAgent creates a new multi-backend SSH agent.
func NewMultiBackendAgent(cfg *MultiBackendConfig) (*MultiBackendAgent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrAgentConnectionFailed)
	}
	if len(cfg.Backends) == 0 {
		return nil, fmt.Errorf("%w: at least one backend is required", ErrAgentConnectionFailed)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	touchHandler := cfg.TouchHandler
	if touchHandler == nil {
		touchHandler = &NoOpTouchHandler{}
	}

	// Determine default backend
	defaultBackend := cfg.DefaultBackend
	if defaultBackend == "" {
		// Use first backend as default
		for name := range cfg.Backends {
			defaultBackend = name
			break
		}
	}

	// Verify default backend exists
	if _, ok := cfg.Backends[defaultBackend]; !ok {
		return nil, fmt.Errorf("%w: default backend '%s' not found", ErrAgentConnectionFailed, defaultBackend)
	}

	logger.Info("multi-backend SSH agent initialized",
		"backends", backendNames(cfg.Backends),
		"default", defaultBackend)

	return &MultiBackendAgent{
		backends:       cfg.Backends,
		defaultBackend: defaultBackend,
		requireTouch:   cfg.RequireTouch,
		touchHandler:   touchHandler,
		logger:         logger,
		keyCache:       make(map[string]*multiBackendCachedKey),
	}, nil
}

// DefaultBackend returns the name of the default backend.
func (a *MultiBackendAgent) DefaultBackend() string {
	return a.defaultBackend
}

// Backends returns the names of all configured backends.
func (a *MultiBackendAgent) Backends() []string {
	return backendNames(a.backends)
}

// List returns all SSH-compatible keys from all backends.
// Keys from the default backend are displayed with simple names.
// Keys from other backends use the extended key ID format.
func (a *MultiBackendAgent) List() ([]*agent.Key, error) {
	if a.locked.Load() {
		return nil, nil // Locked agents return empty list per SSH agent spec
	}

	ctx := context.Background()

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear cache and rebuild
	a.keyCache = make(map[string]*multiBackendCachedKey)

	var agentKeys []*agent.Key

	for backendName, backend := range a.backends {
		keys, err := backend.ListKeys(ctx)
		if err != nil {
			a.logger.Warn("failed to list keys from backend", "backend", backendName, "error", err)
			continue
		}

		for _, ki := range keys {
			fingerprint := ki.Fingerprint
			if fingerprint == "" {
				fingerprint = ssh.FingerprintSHA256(ki.PublicKey)
			}

			// Determine display name based on backend
			displayName := a.formatKeyIDForDisplay(backendName, ki.KeyID)
			fullKeyID := a.formatFullKeyID(backendName, ki.KeyID)

			// Cache for later lookup during Sign
			a.keyCache[fingerprint] = &multiBackendCachedKey{
				backend:   backendName,
				keyID:     ki.KeyID,
				fullKeyID: fullKeyID,
				keyType:   string(ki.KeyType),
				publicKey: ki.PublicKey,
			}

			comment := displayName
			if ki.Comment != "" {
				comment = ki.Comment
			}

			agentKeys = append(agentKeys, &agent.Key{
				Format:  ki.PublicKey.Type(),
				Blob:    ki.PublicKey.Marshal(),
				Comment: comment,
			})
		}
	}

	a.logger.Info("listed keys from all backends", "count", len(agentKeys))
	return agentKeys, nil
}

// Sign signs data with the specified key.
func (a *MultiBackendAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the specified key and flags.
func (a *MultiBackendAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.locked.Load() {
		return nil, ErrAgentLocked
	}

	fingerprint := ssh.FingerprintSHA256(key)

	a.mu.RLock()
	cached, ok := a.keyCache[fingerprint]
	a.mu.RUnlock()

	if !ok {
		// Try to refresh cache
		if _, err := a.List(); err != nil {
			return nil, err
		}

		a.mu.RLock()
		cached, ok = a.keyCache[fingerprint]
		a.mu.RUnlock()

		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrAgentKeyNotFound, fingerprint)
		}
	}

	ctx := context.Background()

	// Request touch confirmation if required
	if a.requireTouch {
		a.logger.Info("requesting touch confirmation", "keyID", cached.fullKeyID)
		if err := a.touchHandler.RequestTouch(ctx, "ssh-sign", cached.fullKeyID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAgentTouchDenied, err)
		}
	}

	// Get the backend for this key
	backend, ok := a.backends[cached.backend]
	if !ok {
		return nil, fmt.Errorf("%w: backend '%s' not found", ErrAgentKeyNotFound, cached.backend)
	}

	// Determine signature algorithm
	algorithm := determineSignatureAlgorithm(key.Type(), flags)

	// Sign via the appropriate backend
	signature, err := backend.Sign(ctx, cached.keyID, data, algorithm)
	if err != nil {
		a.logger.Error("signing failed", "keyID", cached.fullKeyID, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrAgentSignFailed, err)
	}

	a.logger.Debug("signed data", "keyID", cached.fullKeyID, "algorithm", algorithm)

	return &ssh.Signature{
		Format: signatureFormat(key.Type(), flags),
		Blob:   signature,
	}, nil
}

// ResolveKeyID resolves a key ID (simple or extended format) to backend and key name.
// Simple names are resolved against the default backend.
// Extended format (backend:::keyname) specifies the backend explicitly.
func (a *MultiBackendAgent) ResolveKeyID(keyID string) (backendName, resolvedKeyID string, err error) {
	// Try to parse as extended key ID
	backend, _, _, keyname, parseErr := xkms.ParseKeyID(keyID)

	if parseErr != nil {
		// Invalid format
		return "", "", fmt.Errorf("invalid key ID format: %w", parseErr)
	}

	if backend == "" {
		// Simple key name - use default backend
		return a.defaultBackend, keyname, nil
	}

	// Extended format - verify backend exists
	if _, ok := a.backends[backend]; !ok {
		return "", "", fmt.Errorf("backend '%s' not configured", backend)
	}

	return backend, keyname, nil
}

// formatKeyIDForDisplay formats a key ID for display.
// Default backend keys show just the key name.
// Other backends show the extended format.
func (a *MultiBackendAgent) formatKeyIDForDisplay(backendName, keyID string) string {
	if backendName == a.defaultBackend {
		return keyID // Simple name for default backend
	}
	return a.formatFullKeyID(backendName, keyID)
}

// formatFullKeyID creates the extended key ID format.
func (a *MultiBackendAgent) formatFullKeyID(backendName, keyID string) string {
	if backendName == "" {
		return keyID
	}
	// Use format: backend:::keyname (empty type and algo)
	return fmt.Sprintf("%s:::%s", backendName, keyID)
}

// Add is not supported - keys are managed via xkey CLI.
func (a *MultiBackendAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys generate' or 'xkey ssh keys import' to add keys", ErrAgentUnsupportedOp)
}

// Remove is not supported - keys are managed via xkey CLI.
func (a *MultiBackendAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// RemoveAll is not supported - keys are managed via xkey CLI.
func (a *MultiBackendAgent) RemoveAll() error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// Lock locks the agent.
func (a *MultiBackendAgent) Lock(passphrase []byte) error {
	a.locked.Store(true)
	a.logger.Info("agent locked")
	return nil
}

// Unlock unlocks the agent.
func (a *MultiBackendAgent) Unlock(passphrase []byte) error {
	a.locked.Store(false)
	a.logger.Info("agent unlocked")
	return nil
}

// Signers returns signers for all keys.
func (a *MultiBackendAgent) Signers() ([]ssh.Signer, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}

	var signers []ssh.Signer
	for _, key := range keys {
		pubKey, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			continue
		}

		signers = append(signers, &multiBackendSigner{
			agent:   a,
			pubKey:  pubKey,
			comment: key.Comment,
		})
	}

	return signers, nil
}

// Extension handles agent protocol extensions.
func (a *MultiBackendAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// Close closes all backend connections.
func (a *MultiBackendAgent) Close() error {
	a.logger.Info("closing multi-backend agent")
	var errs []error
	for name, backend := range a.backends {
		if err := backend.Close(); err != nil {
			errs = append(errs, fmt.Errorf("backend %s: %w", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing backends: %v", errs)
	}
	return nil
}

// multiBackendSigner implements ssh.Signer.
type multiBackendSigner struct {
	agent   *MultiBackendAgent
	pubKey  ssh.PublicKey
	comment string
}

func (s *multiBackendSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *multiBackendSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pubKey, data)
}

// backendNames returns the names of backends as a sorted slice.
func backendNames(backends map[string]KeyBackend) []string {
	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}
	return names
}

// ParseExtendedKeyID is a convenience function to parse an extended key ID.
// Returns backend (empty for default), and keyname.
func ParseExtendedKeyID(keyID string) (backend, keyname string, err error) {
	b, _, _, k, err := xkms.ParseKeyID(keyID)
	return b, k, err
}

// FormatExtendedKeyID creates an extended key ID with just backend and keyname.
func FormatExtendedKeyID(backend, keyname string) string {
	if backend == "" {
		return keyname
	}
	return fmt.Sprintf("%s:::%s", strings.ToLower(backend), keyname)
}

// Verify MultiBackendAgent implements the required interfaces.
var (
	_ agent.Agent         = (*MultiBackendAgent)(nil)
	_ agent.ExtendedAgent = (*MultiBackendAgent)(nil)
)
