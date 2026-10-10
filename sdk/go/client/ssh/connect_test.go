// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

func testConnectSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

// TestNewHostKeyStore_Opens verifies the re-export constructs a usable
// HostKeyStore over a DAO factory.
func TestNewHostKeyStore_Opens(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	if _, err := store.List(context.Background(), "", ""); err != nil {
		t.Fatalf("List on freshly opened store: %v", err)
	}
}

// TestStartConnect_BuildsArgvAndAgent pins the happy path: StartConnect
// serves the signer over an in-process agent and returns ssh argv/env
// naming the target, exactly as the system ssh client expects.
func TestStartConnect_BuildsArgvAndAgent(t *testing.T) {
	ctx := context.Background()
	store, err := sdkssh.NewHostKeyStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}

	sess, err := sdkssh.StartConnect(ctx, sdkssh.ConnectOptions{
		Host:      "server.example.test",
		Port:      2222,
		User:      "deploy",
		Signer:    testConnectSigner(t),
		HostKeys:  store,
		Owner:     "alice",
		SkipStore: true,
	})
	if err != nil {
		t.Fatalf("StartConnect: %v", err)
	}
	defer func() { _, _, _ = sess.SyncAndStop(context.Background()) }()

	found := false
	for _, a := range sess.Args {
		if a == "deploy@server.example.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("args missing target: %v", sess.Args)
	}
	if len(sess.Env) == 0 {
		t.Fatalf("expected a non-empty Env carrying SSH_AUTH_SOCK")
	}
}

// TestStartConnect_InvalidScopeErrors pins the scope-parse error path: an
// unrecognized Scope string must fail before any agent is started.
func TestStartConnect_InvalidScopeErrors(t *testing.T) {
	_, err := sdkssh.StartConnect(context.Background(), sdkssh.ConnectOptions{
		Host:   "server.example.test",
		Signer: testConnectSigner(t),
		Scope:  "not-a-real-scope",
	})
	var ise *sdkssh.InvalidScopeError
	if !errors.As(err, &ise) {
		t.Fatalf("expected *InvalidScopeError, got %T: %v", err, err)
	}
}
