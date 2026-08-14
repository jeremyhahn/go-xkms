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

// This file carries the shared QUIC handler test fixtures that are NOT
// build-tag specific. It is deliberately untagged: the key-operation tests in
// handlers_keyops_test.go are untagged too, so a helper living in a
// `!frost`-tagged file broke the package's compilation under -tags frost.
// Tagging the consumer instead would have silently dropped keyops coverage
// from frost builds.

package quic

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	backendmocks "github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// extendedKeyStore wraps MockKeyStore so KeyProvider returns an
// ExtendedMockBackend, providing both SymmetricKeyProvider and
// ImportExportBackend on the "software" backend.
// ============================================================================

type extendedKeyStore struct {
	*xkmsmocks.MockKeyStore
	ext *backendmocks.ExtendedMockBackend
}

func (k *extendedKeyStore) KeyProvider() types.KeyProvider {
	return k.ext
}

// createTestServerWithExtended builds a server whose "software" backend
// KeyProvider satisfies both SymmetricKeyProvider and ImportExportBackend.
func createTestServerWithExtended(t *testing.T) (*Server, *xkmsmocks.MockKeyStore, *backendmocks.ExtendedMockBackend) {
	t.Helper()
	xkms.Reset()

	inner := xkmsmocks.NewMockKeyStore()
	ext := backendmocks.NewExtendedMockBackend()
	ks := &extendedKeyStore{MockKeyStore: inner, ext: ext}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, _ := xkms.Get()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, inner, ext
}
