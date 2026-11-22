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

package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newSoftwareResolver builds a Resolver backed by an in-memory software
// KeyProvider so the test exercises the real generate/sign path without
// hardware or disk.
func newSoftwareResolver(t *testing.T) Resolver {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	return ResolverFunc(func(_ context.Context, backendID string) (types.KeyProvider, error) {
		if backendID != "software" {
			return nil, errors.New("unknown backend")
		}
		return kp, nil
	})
}

func TestProvider_DeleteKey(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	keyID := "ssh-user-bob-del"
	if _, err := p.GenerateKey(ctx, "software", keyID, keys.AlgorithmEd25519, 0); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := p.DeleteKey(ctx, "software", keyID, keys.AlgorithmEd25519); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	// After deletion the signer should no longer resolve.
	if _, err := p.Signer(ctx, "software", keyID, keys.AlgorithmEd25519); err == nil {
		t.Fatal("expected error resolving signer for deleted key")
	}
}
