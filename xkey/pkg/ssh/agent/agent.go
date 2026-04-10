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

// Package agent implements an SSH agent that uses xkmsd as its key backend.
// It implements the golang.org/x/crypto/ssh/agent.Agent interface and can be
// served over a Unix domain socket for use with standard SSH clients.
package agent

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go"
)

// Config configures the SSH agent.
type Config struct {
	// XKMSURL is the xkmsd server URL (unix://, grpc://, https://, etc.)
	XKMSURL string

	// Backend is the xkmsd backend to use for SSH keys (e.g., "software", "tpm2")
	Backend string

	// RequireTouch requires touch confirmation for signing operations
	RequireTouch bool

	// TouchHandler handles touch confirmation requests (optional)
	TouchHandler TouchHandler

	// Logger is the structured logger (optional)
	Logger *slog.Logger
}

// XKMSAgent implements ssh/agent.Agent using xkmsd as the key backend.
type XKMSAgent struct {
	client       xkms.Client
	backend      string
	requireTouch bool
	touchHandler TouchHandler
	logger       *slog.Logger

	mu       sync.RWMutex
	locked   atomic.Bool
	keyCache map[string]*cachedKey // fingerprint -> key info
}

// cachedKey stores key information for quick lookup during signing.
type cachedKey struct {
	keyID     string
	keyType   string
	publicKey ssh.PublicKey
}

// New creates a new SSH agent backed by xkmsd.
func New(cfg *Config) (*XKMSAgent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrAgentConnectionFailed)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

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

	touchHandler := cfg.TouchHandler
	if touchHandler == nil {
		touchHandler = &NoOpTouchHandler{}
	}

	return &XKMSAgent{
		client:       client,
		backend:      cfg.Backend,
		requireTouch: cfg.RequireTouch,
		touchHandler: touchHandler,
		logger:       logger,
		keyCache:     make(map[string]*cachedKey),
	}, nil
}

// List returns all SSH-compatible keys from xkmsd.
func (a *XKMSAgent) List() ([]*agent.Key, error) {
	if a.locked.Load() {
		return nil, nil // Locked agents return empty list per SSH agent spec
	}

	ctx := context.Background()
	resp, err := a.client.ListKeys(ctx, a.backend)
	if err != nil {
		a.logger.Error("failed to list keys", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrAgentKeyNotFound, err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear cache and rebuild
	a.keyCache = make(map[string]*cachedKey)

	var keys []*agent.Key
	for _, ki := range resp.Keys {
		// Filter to SSH-compatible key types
		if !isSSHCompatible(ki.KeyType) {
			continue
		}

		// Get the public key
		pubKey, err := a.getSSHPublicKey(ctx, ki.KeyID)
		if err != nil {
			a.logger.Debug("skipping key", "keyID", ki.KeyID, "error", err)
			continue
		}

		fingerprint := ssh.FingerprintSHA256(pubKey)

		// Cache for later lookup during Sign
		a.keyCache[fingerprint] = &cachedKey{
			keyID:     ki.KeyID,
			keyType:   ki.KeyType,
			publicKey: pubKey,
		}

		keys = append(keys, &agent.Key{
			Format:  pubKey.Type(),
			Blob:    pubKey.Marshal(),
			Comment: ki.KeyID,
		})
	}

	a.logger.Info("listed keys", "count", len(keys))
	return keys, nil
}

// Sign signs data with the specified key.
func (a *XKMSAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the specified key and flags.
// This implements the agent.ExtendedAgent interface.
func (a *XKMSAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
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

	// Sign via xkmsd
	resp, err := a.client.Sign(ctx, &xkms.SignRequest{
		Backend: a.backend,
		KeyID:   cached.keyID,
		Data:    data,
		Hash:    algorithm,
	})
	if err != nil {
		a.logger.Error("signing failed", "keyID", cached.keyID, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrAgentSignFailed, err)
	}

	a.logger.Debug("signed data", "keyID", cached.keyID, "algorithm", algorithm)

	return &ssh.Signature{
		Format: signatureFormat(key.Type(), flags),
		Blob:   resp.Signature,
	}, nil
}

// Add is not supported - keys are managed via xkmsd.
func (a *XKMSAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys import' to add keys", ErrAgentUnsupportedOp)
}

// Remove is not supported - keys are managed via xkmsd.
func (a *XKMSAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// RemoveAll is not supported - keys are managed via xkmsd.
func (a *XKMSAgent) RemoveAll() error {
	return fmt.Errorf("%w: use 'xkey ssh keys delete' to remove keys", ErrAgentUnsupportedOp)
}

// Lock locks the agent. While locked, List returns empty and Sign returns error.
func (a *XKMSAgent) Lock(passphrase []byte) error {
	a.locked.Store(true)
	a.logger.Info("agent locked")
	return nil
}

// Unlock unlocks the agent.
func (a *XKMSAgent) Unlock(passphrase []byte) error {
	a.locked.Store(false)
	a.logger.Info("agent unlocked")
	return nil
}

// Signers returns signers for all keys.
func (a *XKMSAgent) Signers() ([]ssh.Signer, error) {
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

		signers = append(signers, &xkmsSigner{
			agent:   a,
			pubKey:  pubKey,
			comment: key.Comment,
		})
	}

	return signers, nil
}

// Extension handles agent protocol extensions.
// This implements the agent.ExtendedAgent interface.
func (a *XKMSAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// Close closes the xkmsd connection.
func (a *XKMSAgent) Close() error {
	a.logger.Info("closing agent")
	return a.client.Close()
}

// getSSHPublicKey retrieves and converts a key's public key to SSH format.
func (a *XKMSAgent) getSSHPublicKey(ctx context.Context, keyID string) (ssh.PublicKey, error) {
	resp, err := a.client.GetKey(ctx, a.backend, keyID)
	if err != nil {
		return nil, err
	}

	// The SDK returns public key as PEM-encoded
	if resp.PublicKeyPEM == "" {
		return nil, fmt.Errorf("%w: no public key data", ErrAgentInvalidKey)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid PEM encoding", ErrAgentInvalidKey)
	}

	// Parse as crypto.PublicKey first, then convert to ssh.PublicKey
	cryptoPubKey, err := parsePublicKey(block.Bytes, resp.KeyType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentInvalidKey, err)
	}

	sshPubKey, err := ssh.NewPublicKey(cryptoPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to convert to SSH key: %v", ErrAgentInvalidKey, err)
	}

	return sshPubKey, nil
}

// xkmsSigner implements ssh.Signer using the agent for signing.
type xkmsSigner struct {
	agent   *XKMSAgent
	pubKey  ssh.PublicKey
	comment string
}

func (s *xkmsSigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *xkmsSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.pubKey, data)
}

// SSHSupportedAlgorithms defines the key algorithms supported by the SSH protocol.
// SSH only supports asymmetric signing algorithms: Ed25519, RSA, ECDSA, and DSA (deprecated).
var SSHSupportedAlgorithms = []types.KeyAlgorithmString{
	types.AlgorithmEd25519,
	types.AlgorithmRSA,
	types.AlgorithmECDSA,
	// types.AlgorithmDSA - deprecated, not included
}

// IsSSHSupportedAlgorithm checks if a key algorithm is supported by the SSH protocol.
// SSH authentication requires asymmetric signing keys: Ed25519, RSA, or ECDSA.
// Symmetric algorithms (AES, HMAC) and key exchange algorithms (X25519) are not supported.
func IsSSHSupportedAlgorithm(algorithm types.KeyAlgorithmString) bool {
	for _, supported := range SSHSupportedAlgorithms {
		if supported.Equals(string(algorithm)) {
			return true
		}
	}
	return false
}

// isSSHCompatible checks if a key type string is compatible with SSH.
// This is a convenience wrapper that handles various string formats from the SDK.
func isSSHCompatible(keyType string) bool {
	// Normalize the key type string
	normalized := strings.ToUpper(keyType)

	// Handle ECDSA curve variants (ecdsa-p256, ecdsa-p384, ecdsa-p521)
	if strings.HasPrefix(normalized, "ECDSA") {
		return true
	}

	// Check against supported algorithms
	return IsSSHSupportedAlgorithm(types.KeyAlgorithmString(keyType))
}

// parsePublicKey parses a public key from DER or raw bytes.
func parsePublicKey(data []byte, keyType string) (crypto.PublicKey, error) {
	switch keyType {
	case "ed25519", "Ed25519", "ED25519":
		if len(data) == ed25519.PublicKeySize {
			return ed25519.PublicKey(data), nil
		}
		// Try parsing as PKIX
		return parsePublicKeyPKIX(data)

	case "rsa", "RSA":
		return parsePublicKeyPKIX(data)

	case "ecdsa", "ECDSA", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		return parsePublicKeyPKIX(data)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// parsePublicKeyPKIX parses a PKIX-encoded public key.
func parsePublicKeyPKIX(data []byte) (crypto.PublicKey, error) {
	// Try to parse as PKIX first
	pubKey, err := parseSubjectPublicKeyInfo(data)
	if err == nil {
		return pubKey, nil
	}

	// Try as raw key formats
	// RSA
	if rsaKey, err := parseRSAPublicKey(data); err == nil {
		return rsaKey, nil
	}

	return nil, fmt.Errorf("unable to parse public key")
}

// determineSignatureAlgorithm determines the signature algorithm based on key type and flags.
func determineSignatureAlgorithm(keyType string, flags agent.SignatureFlags) string {
	switch keyType {
	case ssh.KeyAlgoED25519:
		return "ed25519"
	case ssh.KeyAlgoRSA:
		// Check for SHA-2 signature flags
		if flags&agent.SignatureFlagRsaSha256 != 0 {
			return "rsa-sha256"
		}
		if flags&agent.SignatureFlagRsaSha512 != 0 {
			return "rsa-sha512"
		}
		return "rsa-sha256" // Default to SHA-256 for RSA
	case ssh.KeyAlgoECDSA256:
		return "ecdsa-sha256"
	case ssh.KeyAlgoECDSA384:
		return "ecdsa-sha384"
	case ssh.KeyAlgoECDSA521:
		return "ecdsa-sha512"
	default:
		return "raw"
	}
}

// signatureFormat returns the SSH signature format string.
func signatureFormat(keyType string, flags agent.SignatureFlags) string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		if flags&agent.SignatureFlagRsaSha512 != 0 {
			return ssh.KeyAlgoRSASHA512
		}
		if flags&agent.SignatureFlagRsaSha256 != 0 {
			return ssh.KeyAlgoRSASHA256
		}
		return ssh.KeyAlgoRSASHA256 // Default to rsa-sha2-256
	default:
		return keyType
	}
}

// Verify interface compliance at compile time.
var (
	_ agent.Agent         = (*XKMSAgent)(nil)
	_ agent.ExtendedAgent = (*XKMSAgent)(nil)
)
