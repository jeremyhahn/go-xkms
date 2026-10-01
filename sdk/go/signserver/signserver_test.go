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

package signserver_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/signserver"
)

// TestServerThroughTheSDK builds a server and creates a key using SDK names
// only, the way a CGO-free embedder does.
func TestServerThroughTheSDK(t *testing.T) {
	dir, err := os.MkdirTemp("", "sdkss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	keyStorage, err := xkms.NewFileStorageBackend(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	certStorage, err := xkms.NewFileStorageBackend(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	stateStorage, err := xkms.NewFileStorageBackend(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := xkms.NewSoftwareBackend(&xkms.SoftwareBackendConfig{KeyStorage: keyStorage})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := xkms.NewServiceBackend(&xkms.ServiceBackendConfig{Backend: provider, CertStorage: certStorage})
	if err != nil {
		t.Fatal(err)
	}

	srv, err := signserver.New(context.Background(), signserver.Config{
		SocketPath:   filepath.Join(dir, "sock"),
		AllowedUIDs:  []uint32{uint32(os.Geteuid())},
		Backends:     map[string]xkms.ServiceBackend{"software": backend},
		StateStorage: stateStorage,
		Slots:        []signserver.Slot{{Token: "ike", Keys: []string{"vtep"}}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := srv.CreateKey(context.Background(), signserver.KeyRequest{
		Token: "ike", Label: "vtep", ID: []byte{1}, Curve: "P-256", Backend: "software",
		UserPIN: "user-pin-1234", SOPIN: "so-pin-5678",
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if !key.Created || key.PublicKey == nil {
		t.Fatalf("unexpected key %+v", key)
	}

	_, err = srv.CreateKey(context.Background(), signserver.KeyRequest{Token: "ike", Label: "other"})
	if !errors.Is(err, signserver.ErrKeyNotNamed) {
		t.Fatalf("error = %v, want ErrKeyNotNamed", err)
	}
}

func TestNewRefusesAnEmptyAllowlist(t *testing.T) {
	_, err := signserver.New(context.Background(), signserver.Config{SocketPath: "/nonexistent/sock"})
	if !errors.Is(err, signserver.ErrNoAllowedPeers) {
		t.Fatalf("error = %v, want ErrNoAllowedPeers", err)
	}
}
