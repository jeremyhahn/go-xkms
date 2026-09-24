// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"log/slog"
	"time"

	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

// sshDefaultScope / sshDefaultOwner are the fixed identity the desktop GUI
// uses for SSH keys. The GUI operates a single local custodian, so keys are
// scoped to the user scope under a stable owner; the CLI exposes the full
// scope/owner surface for multi-tenant use.
const (
	sshDefaultScope = "user"
	sshDefaultOwner = "local"
)

// SSHKeyInfo is the frontend-facing view of an SSH key.
type SSHKeyInfo struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	Backend     string `json:"backend"`
	// BackendKeyID is the underlying backend key CN for a backend-backed key
	// (empty for in-process software keys). It lets the unified Keys view
	// correlate this SSH key with its platform key and suppress the duplicate
	// raw-signing-key row.
	BackendKeyID string `json:"backend_key_id"`
	CreatedAt    string `json:"created_at"`
}

// SSHGenerateParams carries the inputs for generating a key from the GUI.
type SSHGenerateParams struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"` // ed25519 | rsa | ecdsa-p256 | ecdsa-p384 | ecdsa-p521
	RSABits   int    `json:"rsa_bits"`
	Comment   string `json:"comment"`
	Backend   string `json:"backend"` // backend ID; empty uses the SSH default backend
}

// SSHBackendInfo describes an SSH-capable backend for the GUI selector.
type SSHBackendInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Category    string `json:"category"`
	Location    string `json:"location"`
	IsDefault   bool   `json:"is_default"`
}

// SSHService exposes SSH key operations to the frontend. Keys are generated on
// whichever backend the user selects in the admin area (software / tpm2 /
// pkcs11 / cloud / remote xkms); for hardware backends the private key never
// leaves the device and signing is delegated. Local backends are served by the
// embedded SSH client (backend-backed keys); a connected remote xkms backend
// is served by the remote transport client.
type SSHService struct {
	ctx         context.Context
	embedded    sshclient.Client
	remoteFn    func() (sshclient.Client, bool)
	registry    backendregistry.Registry
	auditLogger audit.Logger
	logger      *slog.Logger
}

// NewSSHService constructs an SSHService backed by the embedded SSH client.
// embedded carries the local backend provider so a selected local backend
// (tpm2/pkcs11/cloud) mints the key in hardware. It may be nil, in which case
// operations report that SSH is unavailable until configured.
func NewSSHService(embedded sshclient.Client) *SSHService {
	return &SSHService{embedded: embedded}
}

// SetContext is invoked by the Wails startup lifecycle hook.
func (s *SSHService) SetContext(ctx context.Context) { s.ctx = ctx }

// SetEmbeddedClient sets/replaces the embedded SSH client.
func (s *SSHService) SetEmbeddedClient(c sshclient.Client) { s.embedded = c }

// SetRemoteClientFunc registers a factory returning the remote SSH client for a
// connected xkms backend. It returns (client, true) when a remote connection is
// available, (nil, false) otherwise.
func (s *SSHService) SetRemoteClientFunc(fn func() (sshclient.Client, bool)) { s.remoteFn = fn }

// SetRegistry wires the backend registry used for backend selection.
func (s *SSHService) SetRegistry(r backendregistry.Registry) { s.registry = r }

// SetAuditLogger wires the audit logger.
func (s *SSHService) SetAuditLogger(l audit.Logger) { s.auditLogger = l }

// SetLogger wires the structured logger.
func (s *SSHService) SetLogger(l *slog.Logger) { s.logger = l }

// resolveBackend returns the effective backend ID for an operation: the
// explicit choice when provided, else the SSH default from the registry.
func (s *SSHService) resolveBackend(backend string) string {
	if backend != "" {
		return backend
	}
	if s.registry != nil {
		if b, err := s.registry.GetDefault(backendregistry.CapSSH); err == nil && b != nil {
			return b.ID
		}
	}
	return ""
}

// clientFor selects the SSH client for a backend. A remote xkms backend uses
// the remote transport client (the server mints the key on its own backend);
// every other backend uses the embedded client with the backend ID forwarded.
// The returned remote flag reports whether the key is generated server-side.
func (s *SSHService) clientFor(backendID string) (sshclient.Client, bool, error) {
	if s.registry != nil && backendID != "" {
		if b, err := s.registry.Get(backendID); err == nil && b != nil && b.Location == backendregistry.LocationRemote {
			if s.remoteFn != nil {
				if c, ok := s.remoteFn(); ok {
					return c, true, nil
				}
			}
			return nil, false, &SSHRemoteUnavailableError{Backend: backendID}
		}
	}
	if s.embedded == nil {
		return nil, false, ErrSSHUnavailable
	}
	return s.embedded, false, nil
}

// GenerateKey generates an SSH key on the selected backend and returns its
// metadata.
func (s *SSHService) GenerateKey(params SSHGenerateParams) (*SSHKeyInfo, error) {
	start := time.Now()
	if params.Name == "" {
		return nil, ErrSSHMissingName
	}
	if params.Algorithm == "" {
		params.Algorithm = "ed25519"
	}
	backendID := s.resolveBackend(params.Backend)
	client, remote, err := s.clientFor(backendID)
	if err != nil {
		return nil, err
	}

	req := sshclient.GenerateRequest{
		Scope:     sshDefaultScope,
		Owner:     sshDefaultOwner,
		Name:      params.Name,
		Algorithm: params.Algorithm,
		RSABits:   params.RSABits,
		Comment:   params.Comment,
	}
	// For local backends, forward the backend ID so the key is minted there.
	// For a remote xkms backend the server selects its own backend.
	if !remote {
		req.Backend = backendID
	}

	key, err := client.Keys().Generate(s.ctxOrBackground(), req)
	if s.auditLogger != nil {
		if auditErr := s.auditLogger.LogKeyOperation(audit.OpKeyCreated, backendID, params.Name, err == nil, err, time.Since(start).Milliseconds()); auditErr != nil {
			return nil, auditErr
		}
	}
	if err != nil {
		return nil, err
	}
	return keyToInfo(key), nil
}

// ListKeys returns all SSH keys for the GUI's scope/owner.
func (s *SSHService) ListKeys() ([]*SSHKeyInfo, error) {
	client, _, err := s.clientFor("")
	if err != nil {
		return nil, err
	}
	keys, err := client.Keys().List(s.ctxOrBackground(), sshclient.ListKeysRequest{Scope: sshDefaultScope, Owner: sshDefaultOwner})
	if err != nil {
		return nil, err
	}
	out := make([]*SSHKeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyToInfo(k))
	}
	return out, nil
}

// GetKey returns metadata for a single SSH key by name.
func (s *SSHService) GetKey(name string) (*SSHKeyInfo, error) {
	if name == "" {
		return nil, ErrSSHMissingName
	}
	client, _, err := s.clientFor("")
	if err != nil {
		return nil, err
	}
	key, err := client.Keys().Get(s.ctxOrBackground(), sshclient.GetKeyRequest{Scope: sshDefaultScope, Owner: sshDefaultOwner, Name: name})
	if err != nil {
		return nil, err
	}
	return keyToInfo(key), nil
}

// ExportPublic returns the authorized_keys public line for a key.
func (s *SSHService) ExportPublic(name string) (string, error) {
	if name == "" {
		return "", ErrSSHMissingName
	}
	client, _, err := s.clientFor("")
	if err != nil {
		return "", err
	}
	pub, err := client.Keys().ExportPublic(s.ctxOrBackground(), sshclient.ExportRequest{Scope: sshDefaultScope, Owner: sshDefaultOwner, Name: name})
	if err != nil {
		return "", err
	}
	return pub.Line, nil
}

// DeleteKey removes an SSH key by name.
func (s *SSHService) DeleteKey(name string) error {
	start := time.Now()
	if name == "" {
		return ErrSSHMissingName
	}
	client, _, err := s.clientFor("")
	if err != nil {
		return err
	}
	err = client.Keys().Delete(s.ctxOrBackground(), sshclient.DeleteKeyRequest{Scope: sshDefaultScope, Owner: sshDefaultOwner, Name: name})
	if s.auditLogger != nil {
		if auditErr := s.auditLogger.LogKeyOperation(audit.OpKeyDeleted, "", name, err == nil, err, time.Since(start).Milliseconds()); auditErr != nil {
			return auditErr
		}
	}
	return err
}

// ListBackends returns the SSH-capable backends for the GUI selector, with the
// current SSH default flagged.
func (s *SSHService) ListBackends() ([]SSHBackendInfo, error) {
	if s.registry == nil {
		return []SSHBackendInfo{}, nil
	}
	defaultID := ""
	if b, err := s.registry.GetDefault(backendregistry.CapSSH); err == nil && b != nil {
		defaultID = b.ID
	}
	all := s.registry.ListByCapability(backendregistry.CapSSH)
	out := make([]SSHBackendInfo, 0, len(all))
	for _, b := range all {
		out = append(out, SSHBackendInfo{
			ID:          b.ID,
			DisplayName: b.DisplayName,
			Category:    string(b.Category),
			Location:    string(b.Location),
			IsDefault:   b.ID == defaultID,
		})
	}
	return out, nil
}

// SetDefaultBackend sets the default backend for SSH key operations.
func (s *SSHService) SetDefaultBackend(backendID string) error {
	if s.registry == nil {
		return ErrSSHUnavailable
	}
	return s.registry.SetDefault(backendregistry.CapSSH, backendID)
}

// GetDefaultBackend returns the current SSH default backend ID (empty if none).
func (s *SSHService) GetDefaultBackend() string {
	if s.registry == nil {
		return ""
	}
	if b, err := s.registry.GetDefault(backendregistry.CapSSH); err == nil && b != nil {
		return b.ID
	}
	return ""
}

// SupportedAlgorithms returns the SSH key algorithms backendID can generate,
// e.g. ["ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]. The set
// is derived from the backend's registered category (software / tpm2 /
// pkcs11 / phone) via sshclient.SupportedAlgorithms, the single canonical
// mapping shared with the CLI — TPM 2.0 omits "ed25519" because TPM 2.0 has
// no native Ed25519 key object type. An unknown backend ID (including a
// remote xkms backend, whose concrete type is not known client-side) yields
// the full algorithm set; GenerateKey still surfaces the backend's own error
// if the chosen algorithm turns out to be unsupported.
func (s *SSHService) SupportedAlgorithms(backendID string) []string {
	category := ""
	if s.registry != nil && backendID != "" {
		if b, err := s.registry.Get(backendID); err == nil && b != nil {
			category = string(b.Category)
		}
	}
	if category == "" {
		// Auto-detected backends (tpm2, pkcs11, ...) are not in the
		// registry; their well-known IDs double as the category name.
		category = backendID
	}
	return sshclient.SupportedAlgorithms(category)
}

// ctxOrBackground returns the service context, falling back to a background
// context before the Wails startup hook has run.
func (s *SSHService) ctxOrBackground() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// keyToInfo maps an SDK key DTO to the frontend view.
func keyToInfo(k *sshclient.Key) *SSHKeyInfo {
	if k == nil {
		return nil
	}
	return &SSHKeyInfo{
		Name:         k.Name,
		Algorithm:    k.Algorithm,
		PublicKey:    k.PublicKey,
		Fingerprint:  k.Fingerprint,
		Comment:      k.Comment,
		Backend:      k.Backend,
		BackendKeyID: k.BackendKeyID,
		CreatedAt:    k.CreatedAt.Format(time.RFC3339),
	}
}
