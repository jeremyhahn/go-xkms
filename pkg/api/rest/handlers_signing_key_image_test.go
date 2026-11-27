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

package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// imageSigningServicer is a SigningKeyServicer whose SignImage records the
// request it was handed and the password it carried; it serves no other
// call.
type imageSigningServicer struct {
	transport.SigningKeyServicer
	req      *transport.SignImageRequest
	password string
}

func (s *imageSigningServicer) SignImage(_ context.Context, req *transport.SignImageRequest) (*transport.SignedImage, error) {
	s.req = req
	s.password = string(req.Registry.Password)
	return &transport.SignedImage{
		Key:    transport.SigningKeyResolution{Repository: "acme/app", KeyID: "release", Default: true},
		Digest: "sha256:abc", Envelope: []byte(`{"payload":""}`), Certificate: []byte("PEM"),
		Referrer: "sha256:def", ReferrerIndexed: true, AttestationTag: "sha256-abc.att",
	}, nil
}

// TestSigningKeyREST_SignImage proves POST sign-image hands the service the
// reference and registry credentials, returns its signed image, and wipes
// the decoded password once the response is written.
func TestSigningKeyREST_SignImage(t *testing.T) {
	servicer := &imageSigningServicer{}
	c := signingKeyClient(t, signingKeyRouter(servicer))

	signed, err := c.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example.com/acme/app:v1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: []byte("registry-password")},
	})
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc", signed.Digest)
	assert.Equal(t, "release", signed.Key.KeyID)
	assert.True(t, signed.ReferrerIndexed)

	require.NotNil(t, servicer.req)
	assert.Equal(t, "registry.example.com/acme/app:v1", servicer.req.Reference)
	assert.Equal(t, "ci", servicer.req.Registry.Username)
	assert.Equal(t, "registry-password", servicer.password)
	assert.Nil(t, servicer.req.Registry.Password, "the handler wipes the decoded password")
}

// TestSigningKeyREST_SignImageErrors proves a bad body, a malformed
// reference, a service without a CA, a service without an appraiser and a
// nil request each fail with their class.
func TestSigningKeyREST_SignImageErrors(t *testing.T) {
	svc, _ := signingXKMS(t)
	router := signingKeyRouter(svc)
	serve := func(body string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, wire.SigningKeySignImagePath, strings.NewReader(body)))
		return w.Code
	}
	assert.Equal(t, http.StatusBadRequest, serve("{"))
	assert.Equal(t, http.StatusBadRequest, serve(`{"reference":"not a reference"}`))
	assert.Equal(t, http.StatusBadRequest, serve(`{"reference":"registry.example.com/acme/app:v1","registry":{"password":"pw"}}`),
		"a password without a username, before the missing CA is noticed")
	assert.Equal(t, http.StatusServiceUnavailable, serve(`{"reference":"registry.example.com/acme/app:v1"}`), "no CA")

	c := signingKeyClient(t, signingKeyRouter(&xkms.XKMSService{}))
	_, err := c.SignImage(context.Background(), &transport.SignImageRequest{Reference: "registry.example.com/acme/app:v1"})
	assert.Equal(t, &errSigningKeyStatus{code: http.StatusServiceUnavailable}, err)
	_, err = wire.SigningKeyClient{}.SignImage(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}
