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


package unix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestTCGCA_UsesCanonicalRoutes proves the Unix transport's TCG CA calls
// reach the server's canonical /api/v1/ca/tcg/* routes, the same paths the
// REST and QUIC transports use.
func TestTCGCA_UsesCanonicalRoutes(t *testing.T) {
	var paths []string
	tr := &Transport{
		config: transport.DefaultConfig(),
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				rec := httptest.NewRecorder()
				_, _ = rec.WriteString(`{}`)
				return rec.Result(), nil
			}),
		},
		connected: true,
	}
	ctx := context.Background()

	_, err := tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{})
	require.NoError(t, err)
	_, err = tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{})
	require.NoError(t, err)
	_, err = tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{})
	require.NoError(t, err)
	_, err = tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"POST /api/v1/ca/tcg/ek",
		"POST /api/v1/ca/tcg/ak",
		"POST /api/v1/ca/tcg/sign-csr",
		"POST /api/v1/ca/tcg/enroll",
	}, paths)
}

// TestTCGCA_ServerErrorSurfaces proves a refused TCG request is an error,
// not a zero-value success.
func TestTCGCA_ServerErrorSurfaces(t *testing.T) {
	tr := &Transport{
		config: transport.DefaultConfig(),
		httpClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				rec.WriteHeader(http.StatusNotFound)
				return rec.Result(), nil
			}),
		},
		connected: true,
	}
	_, err := tr.IssueEKCertificate(context.Background(), &transport.IssueEKCertificateRequest{})
	assert.Error(t, err)
}
