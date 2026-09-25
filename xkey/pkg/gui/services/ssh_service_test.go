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
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sshclient "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

// newTestSSHService builds an SSHService backed by an embedded SSH client over
// an in-memory software backend, with a registry that has a single
// SSH-capable "software" backend set as the default.
func newTestSSHService(t *testing.T) *SSHService {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshclient.NewBackendProvider(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	})
	if err != nil {
		t.Fatalf("NewBackendProvider: %v", err)
	}
	embedded, err := sshclient.NewEmbedded(sshclient.EmbeddedOptions{
		Backend:         storage.New(),
		BackendProvider: provider,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	registry := backendregistry.NewMemoryRegistry()
	if rerr := registry.Register(&backendregistry.RegisteredBackend{
		ID:           "software",
		Location:     backendregistry.LocationLocal,
		Category:     backendregistry.CategorySoftware,
		DisplayName:  "Software",
		Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSSH: true},
	}); rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}
	if derr := registry.SetDefault(backendregistry.CapSSH, "software"); derr != nil {
		t.Fatalf("SetDefault: %v", derr)
	}

	svc := NewSSHService(embedded)
	svc.SetRegistry(registry)
	svc.SetContext(context.Background())
	return svc
}

func TestSSHService_GenerateListExportDelete(t *testing.T) {
	svc := newTestSSHService(t)

	info, err := svc.GenerateKey(SSHGenerateParams{Name: "laptop", Algorithm: "ed25519", Comment: "me@host"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if info.Name != "laptop" || info.Backend != "software" {
		t.Fatalf("unexpected key info: %+v", info)
	}
	if info.PublicKey == "" || info.Fingerprint == "" {
		t.Fatal("expected public key + fingerprint")
	}

	keys, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Name != "laptop" {
		t.Fatalf("ListKeys returned %+v", keys)
	}

	line, err := svc.ExportPublic("laptop")
	if err != nil {
		t.Fatalf("ExportPublic: %v", err)
	}
	if line == "" {
		t.Fatal("expected non-empty authorized_keys line")
	}

	if err := svc.DeleteKey("laptop"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	keys, err = svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys after delete: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys after delete, got %d", len(keys))
	}
}

func TestSSHService_GetKey(t *testing.T) {
	svc := newTestSSHService(t)

	if _, err := svc.GenerateKey(SSHGenerateParams{Name: "laptop", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info, err := svc.GetKey("laptop")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if info.Name != "laptop" {
		t.Fatalf("unexpected key info: %+v", info)
	}

	if _, err := svc.GetKey("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestSSHService_DefaultAlgorithms(t *testing.T) {
	svc := newTestSSHService(t)

	// RSA-2048 and ECDSA-P256 are the cross-backend defaults (TPM 2.0,
	// SoftHSM2, software). The GUI must generate, list, and export both.
	cases := []struct {
		name      string
		algorithm string
		rsaBits   int
		wantAlgo  string
	}{
		{"gui-ecdsa-p256", "ecdsa-p256", 0, "ecdsa-p256"},
		{"gui-rsa-2048", "rsa", 2048, "rsa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := svc.GenerateKey(SSHGenerateParams{Name: tc.name, Algorithm: tc.algorithm, RSABits: tc.rsaBits})
			if err != nil {
				t.Fatalf("GenerateKey %s: %v", tc.name, err)
			}
			if info.Algorithm != tc.wantAlgo {
				t.Fatalf("expected algorithm %q, got %q", tc.wantAlgo, info.Algorithm)
			}
			if info.Backend != "software" || info.Fingerprint == "" {
				t.Fatalf("unexpected key info: %+v", info)
			}
			line, err := svc.ExportPublic(tc.name)
			if err != nil {
				t.Fatalf("ExportPublic %s: %v", tc.name, err)
			}
			if line == "" {
				t.Fatalf("empty authorized_keys line for %s", tc.name)
			}
		})
	}
}

func TestSSHService_Setters(t *testing.T) {
	svc := NewSSHService(nil)
	if svc.embedded != nil {
		t.Fatal("expected nil embedded client by default")
	}
	if svc.remoteFn != nil {
		t.Fatal("expected nil remoteFn by default")
	}
	if svc.auditLogger != nil {
		t.Fatal("expected nil audit logger by default")
	}
	if svc.logger != nil {
		t.Fatal("expected nil logger by default")
	}

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshclient.NewBackendProvider(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	})
	if err != nil {
		t.Fatalf("NewBackendProvider: %v", err)
	}
	embedded, err := sshclient.NewEmbedded(sshclient.EmbeddedOptions{
		Backend:         storage.New(),
		BackendProvider: provider,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	svc.SetEmbeddedClient(embedded)
	if svc.embedded != embedded {
		t.Fatal("SetEmbeddedClient did not store the client")
	}

	svc.SetRemoteClientFunc(func() (sshclient.Client, bool) { return embedded, true })
	if svc.remoteFn == nil {
		t.Fatal("SetRemoteClientFunc did not store the factory")
	}
	if c, ok := svc.remoteFn(); !ok || c != embedded {
		t.Fatalf("remoteFn() = %v, %v", c, ok)
	}

	auditLogger := audit.NewSlogLogger(slog.Default())
	svc.SetAuditLogger(auditLogger)
	if svc.auditLogger != auditLogger {
		t.Fatal("SetAuditLogger did not store the logger")
	}

	slogger := slog.Default()
	svc.SetLogger(slogger)
	if svc.logger != slogger {
		t.Fatal("SetLogger did not store the logger")
	}
}

func TestSSHService_ClientFor_RemoteBackend(t *testing.T) {
	svc := newTestSSHService(t)

	if rerr := svc.registry.Register(&backendregistry.RegisteredBackend{
		ID:           "remote-1",
		Location:     backendregistry.LocationRemote,
		Category:     backendregistry.CategoryTPM2,
		DisplayName:  "Remote TPM2",
		Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSSH: true},
	}); rerr != nil {
		t.Fatalf("Register: %v", rerr)
	}

	// No remoteFn wired yet: the remote backend is unreachable.
	if _, _, err := svc.clientFor("remote-1"); !errorsIsSSHRemoteUnavailable(err, "remote-1") {
		t.Fatalf("expected SSHRemoteUnavailableError, got %v", err)
	}

	remoteClient := svc.embedded
	svc.SetRemoteClientFunc(func() (sshclient.Client, bool) { return remoteClient, true })

	client, remote, err := svc.clientFor("remote-1")
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	if !remote {
		t.Fatal("expected remote=true for a remote-location backend")
	}
	if client != remoteClient {
		t.Fatal("expected the remote client from remoteFn")
	}
}

func errorsIsSSHRemoteUnavailable(err error, backend string) bool {
	e, ok := err.(*SSHRemoteUnavailableError)
	return ok && e.Backend == backend
}

func TestSSHService_ListBackendsAndDefault(t *testing.T) {
	svc := newTestSSHService(t)

	backends, err := svc.ListBackends()
	if err != nil {
		t.Fatalf("ListBackends: %v", err)
	}
	if len(backends) != 1 || backends[0].ID != "software" || !backends[0].IsDefault {
		t.Fatalf("unexpected backends: %+v", backends)
	}
	if svc.GetDefaultBackend() != "software" {
		t.Fatalf("expected default backend software, got %q", svc.GetDefaultBackend())
	}
}

func TestSSHService_SupportedAlgorithms(t *testing.T) {
	svc := newTestSSHService(t)
	if rerr := svc.registry.Register(&backendregistry.RegisteredBackend{
		ID:           "tpm2-default",
		Location:     backendregistry.LocationLocal,
		Category:     backendregistry.CategoryTPM2,
		DisplayName:  "TPM 2.0",
		Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSSH: true},
	}); rerr != nil {
		t.Fatalf("Register tpm2-default: %v", rerr)
	}

	algos := svc.SupportedAlgorithms("tpm2-default")
	for _, want := range []string{"rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"} {
		if !containsAlgo(algos, want) {
			t.Errorf("SupportedAlgorithms(tpm2-default) = %v, missing %q", algos, want)
		}
	}
	if containsAlgo(algos, "ed25519") {
		t.Fatalf("SupportedAlgorithms(tpm2-default) = %v, must not include ed25519 (TPM 2.0 has no native Ed25519 key object)", algos)
	}

	algos = svc.SupportedAlgorithms("software")
	if !containsAlgo(algos, "ed25519") {
		t.Fatalf("SupportedAlgorithms(software) = %v, expected ed25519 to be included", algos)
	}
}

func TestSSHService_SupportedAlgorithms_AutoDetectedTPM2Filters(t *testing.T) {
	// Live tpm2/pkcs11 backends are auto-detected, NOT registered in the
	// backend registry (same trap as the admin key-count bug). Their
	// well-known IDs must still resolve to the correct category and filter
	// Ed25519 out for tpm2 rather than failing open.
	svc := NewSSHService(nil)
	algos := svc.SupportedAlgorithms("tpm2")
	if containsAlgo(algos, "ed25519") {
		t.Fatalf("SupportedAlgorithms(tpm2, unregistered) = %v, must exclude ed25519", algos)
	}
	if !containsAlgo(algos, "ecdsa-p256") || !containsAlgo(algos, "rsa") {
		t.Fatalf("SupportedAlgorithms(tpm2, unregistered) = %v, want rsa+ecdsa set", algos)
	}
}

func TestSSHService_SupportedAlgorithms_UnknownBackendFailsOpen(t *testing.T) {
	svc := newTestSSHService(t)

	// An unregistered backend ID (e.g. a stale selection) must not panic or
	// error — it falls open to the full algorithm set, matching an unknown
	// backend category.
	algos := svc.SupportedAlgorithms("does-not-exist")
	if !containsAlgo(algos, "ed25519") || len(algos) != 5 {
		t.Fatalf("SupportedAlgorithms(does-not-exist) = %v, want full 5-algorithm set", algos)
	}

	// A nil registry (service not yet wired) must also fail open rather than
	// panic.
	empty := NewSSHService(nil)
	algos = empty.SupportedAlgorithms("anything")
	if !containsAlgo(algos, "ed25519") || len(algos) != 5 {
		t.Fatalf("SupportedAlgorithms with nil registry = %v, want full 5-algorithm set", algos)
	}
}

func containsAlgo(algos []string, want string) bool {
	for _, a := range algos {
		if a == want {
			return true
		}
	}
	return false
}

func TestSSHService_Errors(t *testing.T) {
	svc := newTestSSHService(t)

	if _, err := svc.GenerateKey(SSHGenerateParams{Name: "", Algorithm: "ed25519"}); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := svc.GetKey(""); err == nil {
		t.Fatal("expected error for empty name on GetKey")
	}

	if _, err := svc.ExportPublic(""); err == nil {
		t.Fatal("expected error for empty name on ExportPublic")
	}
	if err := svc.DeleteKey(""); err == nil {
		t.Fatal("expected error for empty name on DeleteKey")
	}

	// No embedded client and no registry => unavailable.
	empty := NewSSHService(nil)
	if _, err := empty.ListKeys(); err == nil {
		t.Fatal("expected ErrSSHUnavailable when no client configured")
	}
}

// errAuditLogger implements audit.Logger with a configurable error from
// LogKeyOperation, used to pin GenerateKey/DeleteKey's audit-failure branch:
// a failed audit write must propagate as the operation's own error.
type errAuditLogger struct {
	err error
}

func (l *errAuditLogger) Log(audit.Entry) error { return nil }
func (l *errAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return l.err
}
func (l *errAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return nil
}
func (l *errAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return nil
}
func (l *errAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error { return nil }
func (l *errAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (l *errAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) error {
	return nil
}
func (l *errAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (l *errAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return nil
}

var _ audit.Logger = (*errAuditLogger)(nil)

func TestSSHService_DeleteKey_AuditFailurePropagates(t *testing.T) {
	svc := newTestSSHService(t)
	if _, err := svc.GenerateKey(SSHGenerateParams{Name: "laptop", Algorithm: "ed25519"}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	auditErr := errors.New("audit backend unavailable")
	svc.SetAuditLogger(&errAuditLogger{err: auditErr})

	err := svc.DeleteKey("laptop")
	if !errors.Is(err, auditErr) {
		t.Fatalf("DeleteKey error = %v, want %v", err, auditErr)
	}
}

// TestSSHService_SetDefaultBackend_NoRegistry pins the guard: without a
// registry there is nothing to record a default in, so the call must
// refuse rather than silently no-op.
func TestSSHService_GetDefaultBackend_NoRegistry(t *testing.T) {
	svc := NewSSHService(nil)
	if got := svc.GetDefaultBackend(); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestSSHService_GetDefaultBackend_NoneSet(t *testing.T) {
	svc := newTestSSHService(t)
	// Clear the default set by newTestSSHService.
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)
	if got := svc.GetDefaultBackend(); got != "" {
		t.Fatalf("expected empty string when no default is set, got %q", got)
	}
}

func TestSSHService_SetDefaultBackend_NoRegistry(t *testing.T) {
	svc := NewSSHService(nil)

	if err := svc.SetDefaultBackend("software"); !errors.Is(err, ErrSSHUnavailable) {
		t.Fatalf("SetDefaultBackend() error = %v, want %v", err, ErrSSHUnavailable)
	}
}

// TestSSHService_SetDefaultBackend_DelegatesToRegistry pins that the call
// actually reaches the registry with the SSH capability and the given
// backend ID, not just that it returns success.
func TestSSHService_SetDefaultBackend_DelegatesToRegistry(t *testing.T) {
	svc := NewSSHService(nil)
	registry := newMockFullRegistry()
	svc.SetRegistry(registry)

	if err := svc.SetDefaultBackend("software"); err != nil {
		t.Fatalf("SetDefaultBackend() error = %v, want nil", err)
	}
	if got := registry.defaults[backendregistry.CapSSH]; got != "software" {
		t.Fatalf("registry default for CapSSH = %q, want %q", got, "software")
	}
}
