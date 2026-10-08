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

package vaultpasskey

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// simAuthenticator is the shared simulated security key.
type simAuthenticator = vaulttest.SimulatedKey

func newSimAuthenticator(pin string) *simAuthenticator { return vaulttest.NewSimulatedKey(pin) }

// testRP is the relying party the test vault service creates passkeys for.
const testRP = "kms.example.com"

func pinSecret(t *testing.T, pin string) *secure.Secret {
	t.Helper()
	s, err := secure.NewSecret(t.Context(), []byte(pin))
	require.NoError(t, err)
	return s
}

func TestEnroll_BuildsThePasskeyCredential(t *testing.T) {
	sim := newSimAuthenticator("123456")
	cred, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), Label: "laptop key", RelyingPartyID: testRP})
	require.NoError(t, err)

	assert.Equal(t, Factor, cred.Factor)
	assert.Equal(t, "laptop key", cred.Label)
	_, onVaultRP := sim.Evaluate(testRP, cred.CredentialID, nil)
	assert.True(t, onVaultRP, "the credential is created for the vault relying party")
	require.Len(t, cred.PRFSalt, 32)
	require.Len(t, cred.Secret, 32)
	// The authenticator received the WebAuthn prf transform of the stored
	// salt, never the salt itself.
	require.Len(t, sim.Received, 1)
	assert.Equal(t, fido2.WebAuthnPRFSalt(cred.PRFSalt), sim.Received[0])
	assert.NotEqual(t, cred.PRFSalt, sim.Received[0])
}

func TestEnroll_PINRefusals(t *testing.T) {
	sim := newSimAuthenticator("123456")
	_, err := Enroll(sim, Options{})
	assert.ErrorIs(t, err, ErrPINRequired)
	_, err = Enroll(sim, Options{PIN: pinSecret(t, "000000"), RelyingPartyID: testRP})
	assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
	assert.Empty(t, sim.Received, "a refused enrollment evaluates nothing")
}

func TestUnlock_SelectsThisAuthenticatorsPasskey(t *testing.T) {
	sim := newSimAuthenticator("123456")
	enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), RelyingPartyID: testRP})
	require.NoError(t, err)

	factors := []transport.PasswordVaultFactor{
		{ID: "p", Factor: "passphrase"},
		{ID: "other", Factor: Factor, CredentialID: []byte("another key"), PRFSalt: bytes.Repeat([]byte{1}, 32), RPID: testRP},
		{ID: "mine", Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: enrolled.PRFSalt, RPID: testRP},
	}
	cred, err := Unlock(sim, factors, Options{PIN: pinSecret(t, "123456")})
	require.NoError(t, err)
	assert.Equal(t, enrolled.CredentialID, cred.CredentialID)
	assert.Equal(t, enrolled.Secret, cred.Secret, "the same credential and salt reproduce the enrolled secret")
	assert.Empty(t, cred.PRFSalt, "unlock sends no salt; the server holds it")
}

func TestUnlock_Refusals(t *testing.T) {
	sim := newSimAuthenticator("123456")
	enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), RelyingPartyID: testRP})
	require.NoError(t, err)
	mine := []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: enrolled.PRFSalt, RPID: testRP}}

	_, err = Unlock(sim, mine, Options{})
	assert.ErrorIs(t, err, ErrPINRequired)
	_, err = Unlock(sim, mine, Options{PIN: pinSecret(t, "000000")})
	assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
	_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: "passphrase"}}, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoPasskeyEnrolled)
	_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: []byte("x"), PRFSalt: []byte("s"), RPID: testRP}}, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoMatchingPasskey)

	// A passkey is evaluated for the relying party its factor records:
	// recorded for another one, this authenticator does not hold it.
	elsewhere := []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: enrolled.PRFSalt, RPID: "other.example.com"}}
	_, err = Unlock(sim, elsewhere, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoMatchingPasskey)
}

func TestEnroll_NeedsTheServersRelyingParty(t *testing.T) {
	sim := newSimAuthenticator("123456")
	_, err := Enroll(sim, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoRelyingParty)
	assert.Empty(t, sim.Received)

	cred, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), RelyingPartyID: testRP})
	require.NoError(t, err)
	assert.Equal(t, testRP, cred.RPID, "the credential names the relying party it was created for")
}

// shortOutputAuthenticator answers with a truncated hmac-secret output.
type shortOutputAuthenticator struct{ *simAuthenticator }

func (s shortOutputAuthenticator) DeriveHMACSecret(cfg *fido2.AuthenticationConfig) (*fido2.AuthenticationResult, error) {
	r, err := s.simAuthenticator.DeriveHMACSecret(cfg)
	if err != nil {
		return nil, err
	}
	r.HMACSecret = r.HMACSecret[:16]
	return r, nil
}

func TestEnroll_RefusesAShortOutput(t *testing.T) {
	sim := shortOutputAuthenticator{newSimAuthenticator("123456")}
	_, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), RelyingPartyID: testRP})
	assert.ErrorIs(t, err, ErrUnexpectedOutput)
}

func TestRandomError(t *testing.T) {
	err := &RandomError{Err: fido2.ErrCredentialNotFound}
	assert.Contains(t, err.Error(), "random source")
	assert.ErrorIs(t, err, fido2.ErrCredentialNotFound)
}

// TestCrossSurface_CLIAndBrowserProduceTheSamePRFInput is the cross-surface
// vector test: for each vector salt, the salt this package (the CLI and GUI
// path) sends the authenticator equals the one the browser's prf extension
// sends, and sdk/ts proves the browser side against the same file.
func TestCrossSurface_CLIAndBrowserProduceTheSamePRFInput(t *testing.T) {
	data, err := os.ReadFile("../fido2/testdata/webauthn_prf_salt_vectors.json")
	require.NoError(t, err)
	var vectors struct {
		Vectors []struct {
			Salt     string `json:"salt"`
			PRFInput string `json:"prf_input"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.NotEmpty(t, vectors.Vectors)

	for _, v := range vectors.Vectors {
		prfSalt, err := hex.DecodeString(v.Salt)
		require.NoError(t, err)

		sim := newSimAuthenticator("123456")
		enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), RelyingPartyID: testRP})
		require.NoError(t, err)
		sim.Received = nil

		_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: prfSalt, RPID: testRP}}, Options{PIN: pinSecret(t, "123456")})
		require.NoError(t, err)
		require.Len(t, sim.Received, 1)
		assert.Equal(t, v.PRFInput, hex.EncodeToString(sim.Received[0]), "CLI path, salt %s", v.Salt)
	}
}

// TestCrossSurface_EnrolledHereUnlocksInABrowser runs a passkey through the
// real vault service: enrolled by this package, then unlocked with the
// secret a browser's prf evaluation of the stored salt yields -- and the
// reverse direction, unlocked here after a lock.
func TestCrossSurface_EnrolledHereUnlocksInABrowser(t *testing.T) {
	svc := vaultservice.New(t).Service
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})
	sim := newSimAuthenticator("123456")
	pin := Options{PIN: pinSecret(t, "123456")}

	before, err := svc.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, testRP, before.PasskeyRPID, "the server advertises its relying party")
	cred, err := Enroll(sim, Options{PIN: pin.PIN, Label: "laptop key", RelyingPartyID: before.PasskeyRPID})
	require.NoError(t, err)
	_, err = svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: cred})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreLock(ctx))

	status, err := svc.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	var stored transport.PasswordVaultFactor
	for _, f := range status.Factors {
		if f.Factor == Factor {
			stored = f
		}
	}
	require.NotEmpty(t, stored.PRFSalt)
	require.Equal(t, testRP, stored.RPID, "the factor records the relying party")

	// A browser: prf with eval.first = the stored salt.
	browserSecret, ok := sim.BrowserPRF(stored.RPID, stored.CredentialID, stored.PRFSalt)
	require.True(t, ok)
	browser := transport.PasswordVaultCredential{Factor: Factor, CredentialID: stored.CredentialID, Secret: browserSecret}
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: browser}))
	require.NoError(t, svc.PasswordStoreLock(ctx))

	// This package, from the vault status alone.
	unlock, err := Unlock(sim, status.Factors, pin)
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: unlock}))

	// A secret evaluated over the raw salt -- no transform -- is refused.
	require.NoError(t, svc.PasswordStoreLock(ctx))
	rawSecret, ok := sim.Evaluate(testRP, stored.CredentialID, stored.PRFSalt)
	require.True(t, ok)
	raw := transport.PasswordVaultCredential{Factor: Factor, CredentialID: stored.CredentialID, Secret: rawSecret}
	err = svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: raw})
	assert.ErrorIs(t, err, staticpw.ErrVaultCredentialRejected)
}

// TestCrossSurface_SecretVectors is the Go half of the vault passkey secret
// vectors (pkg/fido2/testdata/vault_passkey_secret_vectors.json): for an
// authenticator credential with a known secret, Unlock yields exactly the
// factor secret a browser's prf evaluation yields; sdk/ts proves the browser
// half against the same file.
func TestCrossSurface_SecretVectors(t *testing.T) {
	data, err := os.ReadFile("../fido2/testdata/vault_passkey_secret_vectors.json")
	require.NoError(t, err)
	var vectors struct {
		Vectors []struct {
			CredRandom string `json:"cred_random"`
			PRFSalt    string `json:"prf_salt"`
			Secret     string `json:"secret"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.NotEmpty(t, vectors.Vectors)

	for i, v := range vectors.Vectors {
		credRandom, err := hex.DecodeString(v.CredRandom)
		require.NoError(t, err)
		prfSalt, err := hex.DecodeString(v.PRFSalt)
		require.NoError(t, err)
		sim := newSimAuthenticator("123456")
		credentialID := []byte{byte(i), 0xc1}
		sim.Seed(testRP, credentialID, credRandom)

		factor := transport.PasswordVaultFactor{Factor: Factor, CredentialID: credentialID, PRFSalt: prfSalt, RPID: testRP}
		cred, err := Unlock(sim, []transport.PasswordVaultFactor{factor}, Options{PIN: pinSecret(t, "123456")})
		require.NoError(t, err)
		assert.Equal(t, v.Secret, hex.EncodeToString(cred.Secret), "vector %d", i)
	}
}
