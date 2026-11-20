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

package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// TestNewHostServer_PublicRegistrationOnAuthEnforcingNode drives a public
// WebAuthn registration (begin + finish + token mint) over HTTP against a
// REAL qrdb node that enforces authentication, wired as an embedded xkmsd
// node wires it: the host's qrdb client is the node's own client, the
// feature DAOs run as the node's service principal and the request carries
// no identity (the ceremony routes are public). Main answered finish with
// {"error":"internal_error"} here (ruling 742, the webauthn-browser
// integration suite).
func TestNewHostServer_PublicRegistrationOnAuthEnforcingNode(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	node := barriertest.NewPrincipalNode(t)
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{},
		datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	allow := true
	const origin = "https://localhost"
	waCfg := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
		RPID:                    "localhost",
		RPDisplayName:           "xkms",
		RPOrigins:               []string{origin},
		AllowPublicRegistration: &allow,
	})

	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService: svc,
		QRDBClient:  node.Client(),
		DAOFactory:  ds.DAOFactory(),
		WebAuthn:    waCfg,
	})
	require.NoError(t, err)

	// Begin.
	body, err := json.Marshal(map[string]string{"email": "alice@example.com", "display_name": "Alice"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "begin: %s", w.Body.String())
	sessionID := w.Header().Get(webauthnhttp.HeaderSessionID)
	require.NotEmpty(t, sessionID)

	var creation struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	options := w.Body.Bytes()
	if len(creation.PublicKey) > 0 {
		options = creation.PublicKey
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(options))
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{Name: "xkms", ID: "localhost", Origin: origin}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		newFullLengthEC2Credential(t), *parsed)

	// Finish: persists the credential, updates the user and mints the pair.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/finish",
		bytes.NewReader([]byte(attestation)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webauthnhttp.HeaderSessionID, sessionID)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "finish: %s", w.Body.String())

	var auth webauthnhttp.AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &auth))
	require.NotEmpty(t, auth.Token)
	require.NotEmpty(t, auth.RefreshToken)
}

// newFullLengthEC2Credential returns a virtual EC2 credential whose public
// coordinates are full length (a short coordinate fails COSE parsing).
func newFullLengthEC2Credential(t *testing.T) virtualwebauthn.Credential {
	t.Helper()
	for i := 0; i < 128; i++ {
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		parsed, err := x509.ParsePKCS8PrivateKey(cred.Key.Data)
		require.NoError(t, err)
		priv, ok := parsed.(*ecdsa.PrivateKey)
		require.True(t, ok)
		size := (priv.Curve.Params().BitSize + 7) / 8
		if len(priv.X.Bytes()) == size && len(priv.Y.Bytes()) == size {
			return cred
		}
	}
	t.Fatal("no EC2 credential with full-length coordinates")
	return virtualwebauthn.Credential{}
}
