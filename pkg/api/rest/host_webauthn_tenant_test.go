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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newTenantEC2Credential returns a virtual EC2 credential whose public key
// coordinates are full length, which the library's COSE parsing requires.
func newTenantEC2Credential(t *testing.T) virtualwebauthn.Credential {
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
	t.Fatal("could not generate an EC2 credential with full-length coordinates")
	return virtualwebauthn.Credential{}
}

// A host configured with WebAuthnTenantID serves that tenant's accounts over
// an enforcing embedded node whose service principal belongs to the system
// tenant: an invited account's registration, its login, and an
// authenticated account's credentials/begin all complete in the configured
// tenant, as they do in the system tenant.
func TestNewHostServer_WebAuthnCeremoniesInTheConfiguredTenant(t *testing.T) {
	for _, tenantID := range []string{DefaultWebAuthnTenant, "acme"} {
		t.Run(tenantID, func(t *testing.T) {
			node := newEnforcingNode(t)
			if tenantID != DefaultWebAuthnTenant {
				provisionTenant(t, node, tenantID)
			}
			daos := testutil.NewMemoryDAOFactory()
			srv := newTenantWebAuthnHostServer(t, node, daos, tenantID)
			ctx := context.Background()

			// The invitation: an operator provisioned the pending account
			// in the tenant, as CreateUser does for an invitee.
			email := "dana@" + tenantID + ".example"
			invited, err := node.UserService().CreateUser(qrdbsdk.ContextWithTenant(ctx, tenantID), &qrdbuser.CreateUserRequest{
				Username: email,
				Email:    email,
				Name:     "Dana",
				TenantID: tenantID,
				Pending:  true,
			})
			require.NoError(t, err)

			// Redemption runs on the relying party the host builds, over the
			// same credential store.
			wa, err := BuildWebAuthnService(WebAuthnServiceParams{
				Config:      srv.webauthnConfigForTest,
				QRDBClient:  node.Client(),
				DAOFactory:  daos,
				TenantID:    tenantID,
				CallContext: node.ServiceContext,
				UserService: node.UserService(),
			})
			require.NoError(t, err)
			rp := virtualwebauthn.RelyingParty{Name: "example.com", ID: "example.com", Origin: "https://example.com"}
			authenticator := virtualwebauthn.NewAuthenticator()
			credential := newTenantEC2Credential(t)

			regOptions, regSession, err := wa.BeginInviteRegistration(ctx, email)
			require.NoError(t, err, "the invitation lookup finds the invitee in tenant %s", tenantID)
			regJSON, err := json.Marshal(regOptions.Response)
			require.NoError(t, err)
			parsedReg, err := virtualwebauthn.ParseAttestationOptions(string(regJSON))
			require.NoError(t, err)
			var ccr protocol.CredentialCreationResponse
			require.NoError(t, json.Unmarshal([]byte(virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedReg)), &ccr))
			attestation, err := ccr.Parse()
			require.NoError(t, err)
			_, err = wa.FinishInviteRegistration(ctx, regSession, attestation)
			require.NoError(t, err, "the invitee enrols a passkey in tenant %s", tenantID)
			authenticator.AddCredential(credential)
			_, err = node.UserService().UpdateUser(qrdbsdk.ContextWithTenant(ctx, tenantID), &qrdbuser.UpdateUserRequest{
				ID:        invited.ID,
				Lifecycle: qrdbsdk.LifecycleActive,
			})
			require.NoError(t, err)

			// Login through the host's REST surface.
			post := func(path, session, bearer string, body []byte) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if session != "" {
					req.Header.Set(webauthnhttp.HeaderSessionID, session)
				}
				if bearer != "" {
					req.Header.Set("Authorization", "Bearer "+bearer)
				}
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, req)
				return w
			}
			beginBody, err := json.Marshal(map[string]string{"email": email})
			require.NoError(t, err)
			begin := post("/api/v1/webauthn/login/begin", "", "", beginBody)
			require.Equal(t, http.StatusOK, begin.Code, "body: %s", begin.Body.String())
			parsedLogin, err := virtualwebauthn.ParseAssertionOptions(begin.Body.String())
			require.NoError(t, err)
			require.NotEmpty(t, parsedLogin.AllowCredentials, "login begin names the invitee's passkey in tenant %s", tenantID)
			finish := post("/api/v1/webauthn/login/finish", begin.Header().Get(webauthnhttp.HeaderSessionID), "",
				[]byte(virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedLogin)))
			require.Equal(t, http.StatusOK, finish.Code, "the invitee logs in in tenant %s; body: %s", tenantID, finish.Body.String())
			var session webauthnhttp.AuthResponse
			require.NoError(t, json.Unmarshal(finish.Body.Bytes(), &session))
			require.Equal(t, base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, invited.ID)), session.UserID)
			require.NotEmpty(t, session.Token)

			// An authenticated account of the tenant (its administrator)
			// begins adding a passkey to its own account.
			admin, err := node.UserService().CreateUser(qrdbsdk.ContextWithTenant(ctx, tenantID), &qrdbuser.CreateUserRequest{
				Username: "admin@" + tenantID + ".example",
				Email:    "admin@" + tenantID + ".example",
				Name:     "Admin",
				TenantID: tenantID,
			})
			require.NoError(t, err)
			adminHandle := base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, admin.ID))
			pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{
				Subject:  adminHandle,
				TenantID: tenantID,
				Metadata: map[string]string{
					auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
					"username":                  admin.Username,
					"email":                     admin.Email,
				},
			})
			require.NoError(t, err)
			add := post("/api/v1/webauthn/credentials/begin", "", pair.AccessToken, nil)
			require.Equal(t, http.StatusOK, add.Code, "an authenticated account of tenant %s begins adding a passkey; body: %s", tenantID, add.Body.String())
			var options struct {
				PublicKey struct {
					User struct {
						ID string `json:"id"`
					} `json:"user"`
				} `json:"publicKey"`
			}
			require.NoError(t, json.Unmarshal(add.Body.Bytes(), &options))
			require.Equal(t, adminHandle, options.PublicKey.User.ID)
		})
	}
}

// newTenantWebAuthnHostServer is newEnforcingHostServer with the host's
// WebAuthn surface scoped to tenantID and persisting through daos.
func newTenantWebAuthnHostServer(t *testing.T, node *qrdbnode.Node, daos *qrdbsdk.DAOFactory, tenantID string) *tenantHostServer {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	serviceprincipal.RegisterWebAuthnGrant()
	wc := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{RPID: "example.com"})
	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService:         svc,
		QRDBClient:          node.Client(),
		DAOFactory:          daos,
		WebAuthn:            wc,
		WebAuthnTenantID:    tenantID,
		WebAuthnCallContext: node.ServiceContext,
		UserLookup:          node.UserService(),
	})
	require.NoError(t, err)
	require.NotNil(t, srv.tokenIssuer)
	return &tenantHostServer{Server: srv, webauthnConfigForTest: wc}
}

// tenantHostServer is a host server with the relying-party configuration it
// was built from.
type tenantHostServer struct {
	*Server
	webauthnConfigForTest *webauthn.Config
}
