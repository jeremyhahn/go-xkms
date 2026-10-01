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

package serveridtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
)

func TestNewTLSServer_EachServerIsItsOwnIdentity(t *testing.T) {
	a, caA := NewTLSServer(t, http.NotFoundHandler())
	b, _ := NewTLSServer(t, http.NotFoundHandler())
	assert.NotEqual(t, serverid.Of(a.Certificate()), serverid.Of(b.Certificate()))

	pem, err := os.ReadFile(caA)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	id, err := serverid.Probe(context.Background(), a.URL, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	require.NoError(t, err, "the CA file trusts the server")
	assert.Equal(t, serverid.Of(a.Certificate()), id)
}
