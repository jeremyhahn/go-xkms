// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

// Tests for acmeServer's accessors (CA, StorageFactory, Shutdown) and the
// small pure helpers and error types around them (clusterACMEIssuerCN,
// acmeBackendError, acmeInitError.Unwrap). acme_test.go and
// acme_audit_test.go already cover startACMEServer's construction path and
// buildACMERouter/buildACMETLSConfig/buildChallengeMap/
// buildClusterPreSignHooks in depth; this file is scoped to what those leave
// at 0%, per #705 batch D.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	nativeca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// fakeTCGCA satisfies nativeca.TCGCA by embedding it as a nil interface: only
// the accessor under test (acmeServer.CA) ever touches the field, and it
// never calls a method on the value it returns, so no method needs a real
// implementation here.
type fakeTCGCA struct{ nativeca.TCGCA }

// fakeStorageFactory satisfies storage.Factory the same way, for
// acmeServer.StorageFactory.
type fakeStorageFactory struct{ storage.Factory }

// ============================================================================
// acmeServer.CA / acmeServer.StorageFactory
// ============================================================================

func TestAcmeServer_CA_NilReceiver(t *testing.T) {
	var as *acmeServer
	if got := as.CA(); got != nil {
		t.Fatalf("(*acmeServer)(nil).CA() = %v, want nil", got)
	}
}

func TestAcmeServer_CA_ReturnsTheStoredCA(t *testing.T) {
	ca := fakeTCGCA{}
	as := &acmeServer{tcgCA: ca}
	if got := as.CA(); got != ca {
		t.Fatalf("acmeServer.CA() did not return the stored CA")
	}
}

func TestAcmeServer_StorageFactory_NilReceiver(t *testing.T) {
	var as *acmeServer
	if got := as.StorageFactory(); got != nil {
		t.Fatalf("(*acmeServer)(nil).StorageFactory() = %v, want nil", got)
	}
}

func TestAcmeServer_StorageFactory_ReturnsTheStoredFactory(t *testing.T) {
	factory := fakeStorageFactory{}
	as := &acmeServer{storageFactory: factory}
	if got := as.StorageFactory(); got != factory {
		t.Fatalf("acmeServer.StorageFactory() did not return the stored factory")
	}
}

// ============================================================================
// clusterACMEIssuerCN
// ============================================================================

func TestClusterACMEIssuerCN(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "cluster disabled entirely",
			cfg:  &config.Config{},
			want: "",
		},
		{
			name: "cluster enabled but ACME enrollment off",
			cfg:  &config.Config{Cluster: config.ClusterConfig{Enabled: true}},
			want: "",
		},
		{
			name: "enabled with no configured CN keeps default issuance",
			cfg: &config.Config{Cluster: config.ClusterConfig{
				Enabled: true,
				RaftEnrollment: config.RaftEnrollmentConfig{
					ACME: config.RaftACMEEnrollmentConfig{Enabled: true},
				},
			}},
			want: "",
		},
		{
			name: "enabled with a configured cluster CA CN",
			cfg: &config.Config{Cluster: config.ClusterConfig{
				Enabled: true,
				RaftEnrollment: config.RaftEnrollmentConfig{
					ACME:        config.RaftACMEEnrollmentConfig{Enabled: true},
					ClusterCACN: "xkms-cluster-ca",
				},
			}},
			want: "xkms-cluster-ca",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clusterACMEIssuerCN(tc.cfg); got != tc.want {
				t.Errorf("clusterACMEIssuerCN() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ============================================================================
// acmeBackendError / acmeInitError: error mapping.
//
// Each case is driven from the constructor site's own shape (the fields
// startACMEServer actually populates), not a bare Error()-string check: what
// is pinned is that the backend name and the underlying cause both survive
// into the message and remain reachable via errors.Is/errors.As.
// ============================================================================

func TestAcmeBackendError_NamesTheOffendingBackendAndUnwraps(t *testing.T) {
	err := &acmeBackendError{Backend: "software", Err: ErrACMEBackendUnavailable}

	if !errors.Is(err, ErrACMEBackendUnavailable) {
		t.Error("errors.Is(err, ErrACMEBackendUnavailable) = false, want true: Unwrap must expose the sentinel")
	}
	msg := err.Error()
	if !containsAll(msg, "software", "backend", "not available") {
		t.Errorf("acmeBackendError.Error() = %q, want it to name the backend and the condition", msg)
	}
}

func TestAcmeInitError_ErrOnlyUnwraps(t *testing.T) {
	cause := errors.New("listen tcp: address already in use")
	err := &acmeInitError{Stage: "listen on :443", Err: cause}

	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true: an acmeInitError with no Sentinel must still unwrap to Err")
	}
	if got := err.Error(); !containsAll(got, "listen on :443", cause.Error()) {
		t.Errorf("acmeInitError.Error() = %q, want it to carry the stage and the cause", got)
	}
}

func TestAcmeInitError_NoStageDetailWhenErrIsNil(t *testing.T) {
	err := &acmeInitError{Stage: "resolve primary CA", Sentinel: ErrACMECACreate}

	if !errors.Is(err, ErrACMECACreate) {
		t.Error("errors.Is(err, ErrACMECACreate) = false, want true")
	}
	if got := err.Error(); got != "acme: resolve primary CA" {
		t.Errorf("acmeInitError.Error() with no Err = %q, want %q", got, "acme: resolve primary CA")
	}
}

// containsAll reports whether s contains every one of subs, so a message
// assertion can check the load-bearing substrings without pinning exact
// punctuation or ordering.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// ============================================================================
// acmeServer.Shutdown: the non-nil path. TestStartACMEServer_Disabled
// (acme_test.go) already covers the nil-receiver no-op.
// ============================================================================

func TestAcmeServer_Shutdown_ClosesTheAuditLogAndReportsNoError(t *testing.T) {
	as := &acmeServer{
		logger:     silentLogger(),
		doneCh:     make(chan struct{}),
		auditLog:   audit.NewNoOpLogger(),
		httpServer: &http.Server{},
	}
	close(as.doneCh)

	if err := as.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() = %v, want nil", err)
	}
}

// TestAcmeServer_Shutdown_SurfacesTheServerGoroutineError proves a terminal
// error recorded by the ACME HTTPS server's own goroutine (acme.go's `go
// func` in startACMEServer) is what Shutdown reports, even when
// http.Server.Shutdown itself succeeds -- an ACME listener that died with an
// error must not be reported as a clean stop.
func TestAcmeServer_Shutdown_SurfacesTheServerGoroutineError(t *testing.T) {
	goroutineErr := errors.New("accept tcp: use of closed network connection")
	as := &acmeServer{
		logger:     silentLogger(),
		doneCh:     make(chan struct{}),
		auditLog:   audit.NewNoOpLogger(),
		httpServer: &http.Server{},
		err:        goroutineErr,
	}
	close(as.doneCh)

	if err := as.Shutdown(context.Background()); !errors.Is(err, goroutineErr) {
		t.Fatalf("Shutdown() = %v, want %v", err, goroutineErr)
	}
}
