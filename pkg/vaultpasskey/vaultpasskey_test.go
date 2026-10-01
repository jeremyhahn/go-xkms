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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// simAuthenticator simulates a PIN-protected FIDO2 authenticator's
// hmac-secret extension: each credential has a CredRandom that never leaves
// the simulator, and an evaluation returns HMAC-SHA-256(CredRandom, salt)
// for the salt the authenticator RECEIVES -- so a test that reproduces an
// output has proved which salt reached the authenticator.
type simAuthenticator struct {
	pin         string
	rpID        string
	credentials map[string][]byte // credential ID -> CredRandom
	received    [][]byte          // salts evaluated, in order
}

func newSimAuthenticator(pin string) *simAuthenticator {
	return &simAuthenticator{pin: pin, credentials: map[string][]byte{}}
}

func (s *simAuthenticator) checkPIN(pin *secure.Secret) error {
	if pin == nil {
		return fido2.ErrPINRequired
	}
	buf, err := pin.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != s.pin {
		return fido2.ErrInvalidPIN
	}
	return nil
}

func (s *simAuthenticator) EnrollKey(cfg *fido2.EnrollmentConfig) (*fido2.EnrollmentResult, error) {
	if err := s.checkPIN(cfg.PIN); err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	credRandom := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	if _, err := rand.Read(credRandom); err != nil {
		return nil, err
	}
	s.rpID = cfg.RelyingParty.ID
	s.credentials[string(id)] = credRandom
	return &fido2.EnrollmentResult{CredentialID: id, RelyingParty: cfg.RelyingParty}, nil
}

func (s *simAuthenticator) DeriveHMACSecret(cfg *fido2.AuthenticationConfig) (*fido2.AuthenticationResult, error) {
	if err := s.checkPIN(cfg.PIN); err != nil {
		return nil, err
	}
	credRandom, ok := s.credentials[string(cfg.CredentialID)]
	if !ok || cfg.RelyingPartyID != s.rpID {
		return nil, fido2.ErrCredentialNotFound
	}
	s.received = append(s.received, bytes.Clone(cfg.Salt))
	return &fido2.AuthenticationResult{HMACSecret: s.output(credRandom, cfg.Salt)}, nil
}

func (s *simAuthenticator) output(credRandom, salt []byte) []byte {
	mac := hmac.New(sha256.New, credRandom)
	mac.Write(salt)
	return mac.Sum(nil)
}

// browserPRF models a browser's WebAuthn prf evaluation of eval.first for a
// credential on the same authenticator, written from the WebAuthn Level 3
// definition rather than with fido2.WebAuthnPRFSalt.
func (s *simAuthenticator) browserPRF(credentialID, first []byte) []byte {
	salt := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), first...))
	return s.output(s.credentials[string(credentialID)], salt[:])
}

func pinSecret(t *testing.T, pin string) *secure.Secret {
	t.Helper()
	s, err := secure.NewSecret([]byte(pin))
	require.NoError(t, err)
	return s
}

func TestEnroll_BuildsThePasskeyCredential(t *testing.T) {
	sim := newSimAuthenticator("123456")
	cred, err := Enroll(sim, Options{PIN: pinSecret(t, "123456"), Label: "laptop key"})
	require.NoError(t, err)

	assert.Equal(t, Factor, cred.Factor)
	assert.Equal(t, "laptop key", cred.Label)
	assert.Equal(t, RelyingPartyID, sim.rpID)
	require.Len(t, cred.PRFSalt, 32)
	require.Len(t, cred.Secret, 32)
	// The authenticator received the WebAuthn prf transform of the stored
	// salt, never the salt itself.
	require.Len(t, sim.received, 1)
	assert.Equal(t, fido2.WebAuthnPRFSalt(cred.PRFSalt), sim.received[0])
	assert.NotEqual(t, cred.PRFSalt, sim.received[0])
}

func TestEnroll_PINRefusals(t *testing.T) {
	sim := newSimAuthenticator("123456")
	_, err := Enroll(sim, Options{})
	assert.ErrorIs(t, err, ErrPINRequired)
	_, err = Enroll(sim, Options{PIN: pinSecret(t, "000000")})
	assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
	assert.Empty(t, sim.credentials, "a refused enrollment creates no credential")
}

func TestUnlock_SelectsThisAuthenticatorsPasskey(t *testing.T) {
	sim := newSimAuthenticator("123456")
	enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456")})
	require.NoError(t, err)

	factors := []transport.PasswordVaultFactor{
		{ID: "p", Factor: "passphrase"},
		{ID: "other", Factor: Factor, CredentialID: []byte("another key"), PRFSalt: bytes.Repeat([]byte{1}, 32)},
		{ID: "mine", Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: enrolled.PRFSalt},
	}
	cred, err := Unlock(sim, factors, Options{PIN: pinSecret(t, "123456")})
	require.NoError(t, err)
	assert.Equal(t, enrolled.CredentialID, cred.CredentialID)
	assert.Equal(t, enrolled.Secret, cred.Secret, "the same credential and salt reproduce the enrolled secret")
	assert.Empty(t, cred.PRFSalt, "unlock sends no salt; the server holds it")
}

func TestUnlock_Refusals(t *testing.T) {
	sim := newSimAuthenticator("123456")
	enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456")})
	require.NoError(t, err)
	mine := []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: enrolled.PRFSalt}}

	_, err = Unlock(sim, mine, Options{})
	assert.ErrorIs(t, err, ErrPINRequired)
	_, err = Unlock(sim, mine, Options{PIN: pinSecret(t, "000000")})
	assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
	_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: "passphrase"}}, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoPasskeyEnrolled)
	_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: []byte("x"), PRFSalt: []byte("s")}}, Options{PIN: pinSecret(t, "123456")})
	assert.ErrorIs(t, err, ErrNoMatchingPasskey)
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
	_, err := Enroll(sim, Options{PIN: pinSecret(t, "123456")})
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
		enrolled, err := Enroll(sim, Options{PIN: pinSecret(t, "123456")})
		require.NoError(t, err)
		sim.received = nil

		_, err = Unlock(sim, []transport.PasswordVaultFactor{{Factor: Factor, CredentialID: enrolled.CredentialID, PRFSalt: prfSalt}}, Options{PIN: pinSecret(t, "123456")})
		require.NoError(t, err)
		require.Len(t, sim.received, 1)
		assert.Equal(t, v.PRFInput, hex.EncodeToString(sim.received[0]), "CLI path, salt %s", v.Salt)
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

	cred, err := Enroll(sim, Options{PIN: pin.PIN, Label: "laptop key"})
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

	// A browser: prf with eval.first = the stored salt.
	browser := transport.PasswordVaultCredential{Factor: Factor, CredentialID: stored.CredentialID, Secret: sim.browserPRF(stored.CredentialID, stored.PRFSalt)}
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: browser}))
	require.NoError(t, svc.PasswordStoreLock(ctx))

	// This package, from the vault status alone.
	unlock, err := Unlock(sim, status.Factors, pin)
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: unlock}))

	// A secret evaluated over the raw salt -- no transform -- is refused.
	require.NoError(t, svc.PasswordStoreLock(ctx))
	raw := transport.PasswordVaultCredential{Factor: Factor, CredentialID: stored.CredentialID, Secret: sim.output(sim.credentials[string(stored.CredentialID)], stored.PRFSalt)}
	err = svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: raw})
	assert.ErrorIs(t, err, staticpw.ErrVaultCredentialRejected)
}
