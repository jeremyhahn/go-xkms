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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// guardOn turns the mandatory-TLS guard back on for one test (TestMain opts
// the package out of it): with the variable empty, the config field decides.
func guardOn(t *testing.T) {
	t.Helper()
	t.Setenv(transport.EnvAllowInsecureTransport, "")
}

func TestNew_RefusesPlaintextTCP(t *testing.T) {
	guardOn(t)

	_, err := New(transport.WithAddress("10.0.0.1:9090"))
	assert.ErrorIs(t, err, transport.ErrInsecureTransport)

	_, err = NewWithConfig(&transport.Config{Address: "127.0.0.1:9090"})
	assert.ErrorIs(t, err, transport.ErrInsecureTransport, "loopback needs the opt-out too")

	_, err = NewWithConfig(nil)
	assert.ErrorIs(t, err, transport.ErrInsecureTransport, "the default config has TLS disabled")
}

func TestNew_AdmitsSecureOrOptedOutEndpoints(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*transport.Config{
		"tls":              {Address: "10.0.0.1:9090", TLSEnabled: true},
		"unix socket":      {Address: "unix:///run/xkms/xkms.sock"},
		"unix path":        {Address: "unix:xkms.sock"},
		"loopback opt-out": {Address: "127.0.0.1:9090", AllowInsecureTransport: true},
		"tls with opt-out": {Address: "10.0.0.1:9090", TLSEnabled: true, AllowInsecureTransport: true},
	} {
		t.Run(name, func(t *testing.T) {
			tr, err := NewWithConfig(cfg)
			require.NoError(t, err)
			assert.Same(t, cfg, tr.Config())
		})
	}

	tr, err := New(transport.WithAddress("127.0.0.1:9090"), transport.WithAllowInsecureTransport(true))
	require.NoError(t, err)
	assert.True(t, tr.Config().AllowInsecureTransport, "the option sets the opt-out")
}

func TestSignImage_RefusesRegistryCredentialsOverPlaintext(t *testing.T) {
	guardOn(t)
	cfg := &transport.Config{Address: "127.0.0.1:9090", AllowInsecureTransport: true}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// The caller withdraws the opt-out after construction; the credential
	// must still never be sent.
	cfg.AllowInsecureTransport = false
	req := &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	}
	_, err = tr.SignImage(context.Background(), req)
	require.ErrorIs(t, err, transport.ErrInsecureTransport, "refused before the not-connected check, so before any request")
	assert.NotContains(t, err.Error(), "hunter2")
}

func TestSignImage_GuardAdmitsCredentialFreeOrSecureRequests(t *testing.T) {
	guardOn(t)

	plaintext, err := NewWithConfig(&transport.Config{Address: "127.0.0.1:9090", AllowInsecureTransport: true})
	require.NoError(t, err)
	plaintext.Config().AllowInsecureTransport = false
	_, err = plaintext.SignImage(context.Background(), &transport.SignImageRequest{Reference: "registry.example/app:1"})
	assert.ErrorIs(t, err, ErrNotConnected, "a request without registry credentials passes the guard")

	secure, err := NewWithConfig(&transport.Config{Address: "10.0.0.1:9090", TLSEnabled: true})
	require.NoError(t, err)
	_, err = secure.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	})
	assert.ErrorIs(t, err, ErrNotConnected, "credentials over TLS pass the guard")
}
