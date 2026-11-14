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

//go:build integration && fido2

package fido2

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	waprotocol "github.com/go-webauthn/webauthn/protocol"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ceremonySurface bundles the real server-side WebAuthn relying-party surface
// used by the registration ceremony tests: the canonical *webauthn.Service
// (backed by in-memory stores) attached to a real *xkms.XKMSService via
// SetWebAuthn. The XKMSService transport methods (BeginRegistration /
// FinishRegistration) drive the genuine ceremony — there is no simulated server.
type ceremonySurface struct {
	xkmsSvc     *xkms.XKMSService
	webauthnSvc *webauthn.Service
	rpID        string
}

// newCeremonySurface constructs the real ceremony surface. It mirrors the
// construction in pkg/xkms/servicer_fido2_test.go (in-memory user/session/
// credential stores, a fixed RP config) but wires it through the public
// xkms.Initialize/Get singleton so the integration test exercises exactly the
// same XKMSService transport surface the production binaries use.
//
// RP/origin alignment: the WebAuthn verifier rejects an attestation whose
// clientDataJSON origin is not in RPOrigins, or whose RPID does not match. We
// configure RPID "localhost" with RPOrigins ["https://localhost"], and the test
// derives the authenticator origin as "https://" + rpID from the begin options,
// so both sides agree by construction.
func newCeremonySurface(t *testing.T) *ceremonySurface {
	t.Helper()

	const (
		rpID          = "localhost"
		rpDisplayName = "go-xkms Integration RP"
		rpOrigin      = "https://localhost"
	)

	stores := webauthntest.NewStores(t)
	webauthnSvc, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          rpID,
			RPDisplayName: rpDisplayName,
			RPOrigins:     []string{rpOrigin},
			// These tests exercise first-passkey sign-up for an unknown
			// email, which is closed unless the relying party opts in.
			AllowPublicRegistration: openRegistration(),
		},
		UserStore:       stores.Users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err, "construct canonical WebAuthn relying-party service")

	// Initialize the XKMSService singleton on in-memory software backends, the
	// same minimal config the unit test's setupService helper uses. Reset first
	// so repeated runs start from a clean global state.
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	// Build a real in-memory software backend through the production factory path
	// (software.NewBackend -> xkms.New). The registration ceremony itself only
	// touches the WebAuthn service, but XKMSService.Initialize requires at least
	// one functioning Backend, so we provide a genuine one rather than a stub.
	keyProvider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err, "construct software key provider")

	softwareBackend, err := xkms.New(&xkms.BackendConfig{
		Backend:     keyProvider,
		CertStorage: storage.New(),
	})
	require.NoError(t, err, "construct software backend")

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": softwareBackend,
		},
		DefaultBackend: "software",
	}), "initialize XKMSService")

	xkmsSvc, err := xkms.Get()
	require.NoError(t, err, "retrieve XKMSService singleton")

	// Attach the real WebAuthn service: BeginRegistration / FinishRegistration on
	// the XKMSService now delegate to the genuine relying-party ceremony.
	xkmsSvc.SetWebAuthn(webauthnSvc)

	return &ceremonySurface{
		xkmsSvc:     xkmsSvc,
		webauthnSvc: webauthnSvc,
		rpID:        rpID,
	}
}

// openRegistration returns a true AllowPublicRegistration value, as the
// pkg/webauthn tests do for the same first-passkey flow.
func openRegistration() *bool {
	b := true
	return &b
}

// runRegistrationCeremony drives the full registration ceremony against the real
// server-side WebAuthn service using the supplied FIDO2 handler (virtual device
// in CI, or a real authenticator when hardware-gated). It returns once the
// credential is verified and persisted, failing the test on any deviation.
//
// Flow:
//  1. svcXKMS.BeginRegistration -> opaque session ID + CredentialCreation JSON.
//  2. Parse the options JSON to recover challenge, RPID, RPName, user handle.
//  3. handler.RegisterWebAuthn drives the CTAP2 authenticator to emit a real
//     attestation over that exact challenge/origin/RP.
//  4. svcXKMS.FinishRegistration verifies the attestation signature server-side
//     and persists the credential.
//  5. Assert success + credential persistence via the credential store.
func runRegistrationCeremony(t *testing.T, surface *ceremonySurface, handler *fido2.FIDO2Handler, username string) {
	t.Helper()
	defer CleanupCredential(t, handler)

	ctx := context.Background()

	// Step 1: Begin registration through the XKMSService transport surface.
	beginResp, err := surface.xkmsSvc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       username,
		DisplayName: username,
	})
	require.NoError(t, err, "BeginRegistration")
	require.NotEmpty(t, beginResp.SessionID, "session ID")
	require.NotEmpty(t, beginResp.OptionsJSON, "options JSON")

	// Step 2: Parse the options JSON the server issued (a CredentialCreation) to
	// recover the challenge and relying-party parameters the authenticator must
	// bind to.
	var options waprotocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options), "parse CredentialCreation options")

	challenge := []byte(options.Response.Challenge)
	require.NotEmpty(t, challenge, "server challenge")

	rpID := options.Response.RelyingParty.ID
	rpName := options.Response.RelyingParty.Name
	require.Equal(t, surface.rpID, rpID, "RPID from options must match configured RP")

	// Origin MUST match the service's configured RPOrigins. The service is
	// configured with origin "https://" + rpID, so derive it identically here.
	origin := "https://" + rpID

	// Resolve the canonical user handle the server bound to this ceremony. Using
	// the service's own user record (rather than re-decoding options.Response.User.ID)
	// guarantees the attestation's user handle matches what the verifier expects.
	user, err := surface.webauthnSvc.GetUserByEmail(ctx, username)
	require.NoError(t, err, "resolve ceremony user")
	userID := user.WebAuthnID()
	require.NotEmpty(t, userID, "user handle")

	// Step 3: Drive the REAL CTAP2 authenticator to produce an attestation over
	// the server-issued challenge. The virtual device auto-confirms user presence;
	// a physical YubiKey requires a touch within the timeout.
	t.Logf("Driving authenticator registration for user %q (rpID=%q origin=%q)", username, rpID, origin)
	att, err := handler.RegisterWebAuthn(fido2.WebAuthnRegistrationOptions{
		Challenge:               challenge,
		Origin:                  origin,
		RPID:                    rpID,
		RPName:                  rpName,
		UserID:                  userID,
		UserName:                username,
		UserDisplayName:         username,
		RequireUserVerification: false,
		Timeout:                 30 * time.Second,
	})
	require.NoError(t, err, "RegisterWebAuthn (authenticator attestation)")
	require.NotEmpty(t, att.CredentialID, "attested credential ID")
	require.NotEmpty(t, att.PublicKeyCredentialJSON, "PublicKeyCredential JSON")

	// Step 4: Finish registration. This is the load-bearing assertion: the server
	// re-parses the PublicKeyCredential, verifies the attestation signature over
	// the clientDataHash + authenticatorData, checks RP/origin/challenge, and
	// persists the credential. Any signature or RP/origin mismatch fails here.
	finishResp, err := surface.xkmsSvc.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(att.PublicKeyCredentialJSON),
	})
	require.NoError(t, err, "FinishRegistration (server-side attestation verification)")
	require.True(t, finishResp.Success, "registration reported success")
	require.NotEmpty(t, finishResp.CredentialID, "persisted credential ID")

	// Step 5: Prove the credential was actually persisted by the ceremony, the
	// same way the unit test asserts persistence.
	creds, err := surface.webauthnSvc.GetCredentials(ctx, userID)
	require.NoError(t, err, "load persisted credentials")
	require.Len(t, creds, 1, "exactly one credential persisted")

	registered, err := surface.webauthnSvc.IsRegistered(ctx, userID)
	require.NoError(t, err, "IsRegistered")
	assert.True(t, registered, "user reported as registered")

	t.Logf("Registration ceremony succeeded: credential %x persisted for %q", att.CredentialID, username)
}

// TestFIDO2Registration_VirtualAuthenticator_EndToEnd proves the full WebAuthn
// registration enrollment works end-to-end against the REAL server-side
// XKMSService ceremony, driven by xkey's in-process virtual CTAP2 authenticator.
//
// This is the canonical CI proof that a real authenticator's attestation is
// accepted (signature-verified) by the server. No hardware, no browser.
//
// The virtual device is always available in CI, so this runs unconditionally;
// it only skips if the virtual enumerator itself fails to initialize.
func TestFIDO2Registration_VirtualAuthenticator_EndToEnd(t *testing.T) {
	cfg := LoadFIDO2TestConfig()

	// The native virtual CTAP2 device is always available in CI (no hardware, no
	// UHID). CreateVirtualHandler fails the test via require if the virtual
	// enumerator cannot initialize, which surfaces the real reason rather than
	// silently skipping.
	handler := cfg.CreateVirtualHandler(t)
	require.NotNil(t, handler, "virtual FIDO2 handler")

	surface := newCeremonySurface(t)
	username := GenerateUniqueUsername("fido2-reg")

	runRegistrationCeremony(t, surface, handler, username)
}
