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

package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestNewServer_NilAuthenticatorRejected proves the gRPC constructor is
// fail-closed. Before this guard a nil Authenticator was silently replaced with
// a NoOp authenticator, so an SDK caller that forgot to configure
// authentication got a fully unauthenticated server without any signal.
func TestNewServer_NilAuthenticatorRejected(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	server, err := NewServer(&ServerConfig{
		Port:   0,
		Logger: discardLogger(),
	})

	require.ErrorIs(t, err, ErrAuthenticatorRequired)
	assert.Nil(t, server, "no server must be returned when authentication is unconfigured")
}

// TestNewServer_ExplicitNoOpAuthenticator proves the NoOp authenticator is
// still selectable — but only when the caller asks for it by name.
func TestNewServer_ExplicitNoOpAuthenticator(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	server, err := NewServer(&ServerConfig{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        discardLogger(),
	})

	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, "noop", server.authenticator.Name())
}
