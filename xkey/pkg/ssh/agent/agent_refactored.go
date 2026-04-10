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
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/sdk/go"
)

// AgentConfig configures the SSH agent with support for both xkmsd and standalone modes.
type AgentConfig struct {
	// XKMSURL is the xkmsd server URL (unix://, grpc://, https://, etc.)
	// If empty, the agent runs in standalone mode with local key storage.
	XKMSURL string

	// Backend is the xkmsd backend to use for SSH keys (e.g., "software", "tpm2")
	// In standalone mode, this is ignored.
	Backend string

	// LocalStorePath is the path for local key storage in standalone mode.
	// Defaults to ~/.config/xkey/ssh/keys
	LocalStorePath string

	// RequireTouch requires touch confirmation for signing operations
	RequireTouch bool

	// TouchHandler handles touch confirmation requests (optional)
	TouchHandler TouchHandler

	// Logger is the structured logger (optional)
	Logger *slog.Logger
}

// Agent implements ssh/agent.Agent using a KeyBackend for key operations.
// It supports both xkmsd (remote) and local (standalone) key storage.
type Agent struct {
	backend      KeyBackend
	requireTouch bool
	touchHandler TouchHandler
	logger       *slog.Logger
	standalone   bool

	mu       sync.RWMutex
	locked   atomic.Bool
	keyCache map[string]*cachedKey // fingerprint -> key info
}

// NewAgent creates a new SSH agent.
// If XKMSURL is provided, it connects to xkmsd.
// Otherwise, it uses local key storage (standalone mode).
func NewAgent(cfg *AgentConfig) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrAgentConnectionFailed)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	touchHandler := cfg.TouchHandler
	if touchHandler == nil {
		touchHandler = &NoOpTouchHandler{}
	}

	var backend KeyBackend
	var standalone bool
	var err error

	if cfg.XKMSURL != "" {
		// XKMSd mode
		backend, err = createXKMSdBackend(cfg, logger)
		if err != nil {
			return nil, err
		}
		standalone = false
		logger.Info("SSH agent using xkmsd backend", "url", cfg.XKMSURL, "backend", cfg.Backend)
	} else {
		// Standalone mode
		backend, err = createLocalBackend(cfg, logger)
		if err != nil {
			return nil, err
		}
		standalone = true
		logger.Info("SSH agent using local storage (standalone mode)", "path", cfg.LocalStorePath)
	}

	return &Agent{
		backend:      backend,
		requireTouch: cfg.RequireTouch,
		touchHandler: touchHandler,
		logger:       logger,
		standalone:   standalone,
		keyCache:     make(map[string]*cachedKey),
	}, nil
}

// createXKMSdBackend creates a backend connected to xkmsd.
func createXKMSdBackend(cfg *AgentConfig, logger *slog.Logger) (KeyBackend, error) {
	client, err := xkms.NewFromURL(cfg.XKMSURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentConnectionFailed, err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentConnectionFailed, err)
	}

	// Verify connection by checking health
	if _, err := client.Health(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("%w: health check failed: %v", ErrAgentConnectionFailed, err)
	}

	backendName := cfg.Backend
	if backendName == "" {
		backendName = "software"
	}

	return NewXKMSdBackend(client, backendName)
}

// createLocalBackend creates a backend for local key storage.
func createLocalBackend(cfg *AgentConfig, logger *slog.Logger) (KeyBackend, error) {
	storePath := cfg.LocalStorePath
	if storePath == "" {
		storePath = DefaultLocalStorePath()
	}

	var storageBackend storage.Backend
	var err error

	storageBackend, err = file.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create local storage: %v", ErrAgentConnectionFailed, err)
	}

	return NewLocalBackend(&LocalBackendConfig{
		Backend: storageBackend,
	})
}

// IsStandalone returns true if the agent is running in standalone mode.
func (a *Agent) IsStandalone() bool {
	return a.standalone
}

// Backend returns the underlying key backend.
func (a *Agent) Backend() KeyBackend {
	return a.backend
}

// List returns all SSH-compatible keys.
func (a *Agent) List() ([]*agent.Key, error) {
	if a.locked.Load() {
		return nil, nil // Locked agents return empty list per SSH agent spec
	}

	ctx := context.Background()
	keys, err := a.backend.ListKeys(ctx)
	if err != nil {
		a.logger.Error("failed to list keys", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrAgentKeyNotFound, err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear cache and rebuild
	a.keyCache = make(map[string]*cachedKey)

	var agentKeys []*agent.Key
	for _, ki := range keys {
		fingerprint := ki.Fingerprint

		// Cache for later lookup during Sign
		a.keyCache[fingerprint] = &cachedKey{
			keyID:     ki.KeyID,
			keyType:   string(ki.KeyType),
			publicKey: ki.PublicKey,
		}

		comment := ki.Comment
		if comment == "" {
			comment = ki.KeyID
		}

		agentKeys = append(agentKeys, &agent.Key{
			Format:  ki.PublicKey.Type(),
			Blob:    ki.PublicKey.Marshal(),
			Comment: comment,
		})
	}

	a.logger.Info("listed keys", "count", len(agentKeys))
	return agentKeys, nil
}

// Sign signs data with the specified key.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the specified key and flags.
// This implements the agent.ExtendedAgent interface.
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.locked.Load() {
		return nil, ErrAgentLocked
	}

	// Find the key ID from public key
	fingerprint := ssh.FingerprintSHA256(key)

	a.mu.RLock()
	cached, ok := a.keyCache[fingerprint]
	a.mu.RUnlock()

	if !ok {
		// Try to refresh cache and find key
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
		a.logger.Info("requesting touch confirmation", "keyID", cached.keyID)
		if err := a.touchHandler.RequestTouch(ctx, "ssh-sign", cached.keyID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrAgentTouchDenied, err)
		}
	}

	// Determine signature algorithm based on key type and flags
	algorithm := determineSignatureAlgorithm(key.Type(), flags)

	// Sign via backend
	signature, err := a.backend.Sign(ctx, cached.keyID, data, algorithm)
	if err != nil {
		a.logger.Error("signing failed", "keyID", cached.keyID, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrAgentSignFailed, err)
	}

	a.logger.Debug("signed data", "keyID", cached.keyID, "algorithm", algorithm)

	return &ssh.Signature{
		Format: signatureFormat(key.Type(), flags),
		Blob:   signature,
	}, nil
}

// Add is not supported - keys are managed via xkey CLI.
func (a *Agent) Add(key agent.AddedKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys generate' or 'xkey ssh keys import' to add keys", ErrAgentUnsupportedOp)
}

// Remove is not supported - keys are managed via xkey CLI.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// RemoveAll is not supported - keys are managed via xkey CLI.
func (a *Agent) RemoveAll() error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// Lock locks the agent. While locked, List returns empty and Sign returns error.
func (a *Agent) Lock(passphrase []byte) error {
	a.locked.Store(true)
	a.logger.Info("agent locked")
	return nil
}

// Unlock unlocks the agent.
func (a *Agent) Unlock(passphrase []byte) error {
	a.locked.Store(false)
	a.logger.Info("agent unlocked")
	return nil
}

// Signers returns signers for all keys.
func (a *Agent) Signers() ([]ssh.Signer, error) {
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

		signers = append(signers, &agentSigner{
			agent:   a,
			pubKey:  pubKey,
			comment: key.Comment,
		})
	}

	return signers, nil
}

// Extension handles agent protocol extensions.
// This implements the agent.ExtendedAgent interface.
func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// Close closes the backend connection.
func (a *Agent) Close() error {
	a.logger.Info("closing agent")
	return a.backend.Close()
}

// agentSigner implements ssh.Signer using the agent for signing.
type agentSigner struct {
	agent   *Agent
	pubKey  ssh.PublicKey
	comment string
}

func (s *agentSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *agentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pubKey, data)
}

// DefaultLocalStorePath returns the default path for local SSH key storage.
func DefaultLocalStorePath() string {
	return defaultConfigPath("ssh/keys")
}

// defaultConfigPath returns a path within the xkey config directory.
func defaultConfigPath(subpath string) string {
	// Use XDG_CONFIG_HOME if set, otherwise ~/.config
	configDir := getConfigDir()
	return configDir + "/xkey/" + subpath
}

// getConfigDir returns the user's config directory.
func getConfigDir() string {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return xdgConfig
	}
	if home := os.Getenv("HOME"); home != "" {
		return home + "/.config"
	}
	return "/tmp"
}

// Verify Agent implements the required interfaces at compile time.
var (
	_ agent.Agent         = (*Agent)(nil)
	_ agent.ExtendedAgent = (*Agent)(nil)
)
