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

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/releasesigningtest"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

const signTool = "attestation.signing_key.sign"

func newReleaseSigningMCP(t *testing.T, f *releasesigningtest.Fixture) *Server {
	t.Helper()
	s, err := NewServer(&Config{XKMSService: f.Service, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return s
}

func invokeSign(t *testing.T, s *Server, params any) (*transport.SignReleaseCoRIMResponse, error) {
	t.Helper()
	var out transport.SignReleaseCoRIMResponse
	if err := invokeOIDC(t, s, releasesigningtest.Tenant, "release-pipeline", signTool, params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TestReleaseSigningMCP_SignsWithTheCallersKey: the caller's tenant key signs
// and the result verifies; a malformed CoRIM is InvalidParams.
func TestReleaseSigningMCP_SignsWithTheCallersKey(t *testing.T) {
	f := releasesigningtest.New(t, releasesigningtest.Tenant, releasesigningtest.SignPermission)
	s := newReleaseSigningMCP(t, f)

	resp, err := invokeSign(t, s, releasesigningtest.Request(releasesigningtest.UnsignedCoRIM(t)))
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resp.KeyID)
	verified, err := refvalue.VerifySigned(resp.SignedCoRIM, refvalue.VerifyOptions{PublicKey: f.ReleaseKey})
	require.NoError(t, err)
	assert.Equal(t, releasesigningtest.Repository, verified.Signer)

	_, err = invokeSign(t, s, releasesigningtest.Request([]byte{0xff}))
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
}

// TestReleaseSigningMCP_Refusals: no sign permission and a foreign tenant's
// key both refuse, and neither returns a signature.
func TestReleaseSigningMCP_Refusals(t *testing.T) {
	corim := releasesigningtest.UnsignedCoRIM(t)

	f := releasesigningtest.New(t, releasesigningtest.Tenant, "attestation_signing_keys:get")
	resp, err := invokeSign(t, newReleaseSigningMCP(t, f), releasesigningtest.Request(corim))
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeForbidden, keyErr.Code)
	assert.Nil(t, resp)

	f = releasesigningtest.New(t, releasesigningtest.ForeignTenant, releasesigningtest.SignPermission)
	resp, err = invokeSign(t, newReleaseSigningMCP(t, f), releasesigningtest.Request(corim))
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
	assert.Nil(t, resp)
}
