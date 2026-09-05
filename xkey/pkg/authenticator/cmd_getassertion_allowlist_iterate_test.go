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

// Regression tests for issue #347: authenticatorGetAssertion must iterate the
// allowList instead of aborting on the first entry whose key material the key
// backend no longer holds.
//
// The field failure mode: the server's credential table survives a daemon
// re-provision, so it keeps offering allowList entries whose key material was
// wiped from the key backend. The stored record still loads from credential
// storage, so the stale entry was selected first and the ceremony died at
// signing time with "key not found" — the valid credential behind it was never
// tried. Per CTAP 2.1 §6.2 step 1 such an entry is simply not applicable; the
// ceremony must proceed over the loadable candidates and report
// CTAP2_ERR_NO_CREDENTIALS only when none remain.
//
// These tests reuse bindingTestProvider from
// cmd_makecredential_backend_binding_test.go as the in-process key provider.

package authenticator

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/require"
)

// errLoadKeyFault simulates a key backend whose store is broken (I/O fault),
// as opposed to a key that is merely absent. Its message deliberately avoids
// the "not found" wording so mapKeyBackendError classifies it as a backend
// failure, matching a real storage-layer fault.
var errLoadKeyFault = errors.New("keybackend test: storage I/O fault")

// faultingLoadKeyBackend wraps a real FIDO2KeyBackend and fails LoadKey with a
// non-not-found error for one designated credential ID, leaving every other
// operation untouched. It models a backend whose store is broken for a read —
// the case that must ABORT the ceremony rather than be skipped.
type faultingLoadKeyBackend struct {
	keybackend.FIDO2KeyBackend
	faultID []byte
}

// LoadKey returns errLoadKeyFault for the designated credential ID and
// delegates to the wrapped backend otherwise.
func (b *faultingLoadKeyBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	if bytes.Equal(credentialID, b.faultID) {
		return nil, errLoadKeyFault
	}
	return b.FIDO2KeyBackend.LoadKey(credentialID, algorithm)
}

// newAllowListIterateAuthenticator builds an authenticator whose KeyBackend is
// a single software BackendAdapter over an isolated bindingTestProvider, so
// key material presence can be controlled independently of credential storage.
func newAllowListIterateAuthenticator(t *testing.T, backend keybackend.FIDO2KeyBackend) *Authenticator {
	t.Helper()

	config := &Config{
		UserPresenceHandler:        NewAutoGrantHandler(),
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256},
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		PINMinLength:               4,
		PINMaxRetries:              8,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		Storage:                    NewMemoryStorage(),
		KeyBackend:                 backend,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err, "NewAuthenticator must not fail")
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// newSoftwareKeyBackend returns a fresh software-backed adapter.
func newSoftwareKeyBackend(t *testing.T) *keybackend.BackendAdapter {
	t.Helper()
	provider := newBindingTestProvider(xkms.BackendTypeSoftware, false)
	return keybackend.NewBackendAdapter(provider, xkms.BackendTypeSoftware)
}

// registerBackendCredential runs a full MakeCredential ceremony so the
// credential exists in BOTH credential storage and the key backend, and
// returns its credential ID.
func registerBackendCredential(t *testing.T, auth *Authenticator, rpID, userName string) []byte {
	t.Helper()

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: rpID, Name: "AllowList Iterate Test RP"}
	user := User{ID: []byte("uid-" + userName), Name: userName}
	params := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash, rp, user, params, nil)
	require.NoError(t, err, "MakeCredential must succeed")

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err, "ParseAuthData must succeed")
	require.NotEmpty(t, authData.CredentialID)
	return authData.CredentialID
}

// storeStaleCredential stores a credential record in credential storage whose
// key material does NOT exist on the key backend — exactly the state a
// re-provisioned daemon leaves behind (issue #347's poison entries).
func storeStaleCredential(t *testing.T, auth *Authenticator, rpID string) []byte {
	t.Helper()
	cred := createAssertionTestCredential(t, auth, rpID, false)
	return cred.CredentialID
}

// allowListOf builds public-key credential descriptors in the given order.
func allowListOf(ids ...[]byte) []CredentialDescriptor {
	descs := make([]CredentialDescriptor, 0, len(ids))
	for _, id := range ids {
		descs = append(descs, CredentialDescriptor{Type: "public-key", ID: id})
	}
	return descs
}

// TestGetAssertion_AllowListSkipsStaleEntries is the field regression for
// issue #347: the server offers [stale, stale, valid] and the ceremony must
// succeed with the valid credential instead of aborting on the first entry.
// This test fails on the pre-fix code, which selected the first stored record
// and died in buildSignedAssertion when LoadKey returned ErrKeyNotFound.
func TestGetAssertion_AllowListSkipsStaleEntries(t *testing.T) {
	rpID := "localhost"
	auth := newAllowListIterateAuthenticator(t, newSoftwareKeyBackend(t))

	stale1 := storeStaleCredential(t, auth, rpID)
	stale2 := storeStaleCredential(t, auth, rpID)
	valid := registerBackendCredential(t, auth, rpID, "valid@example.com")

	resp, err := auth.GetAssertion(generateTestClientDataHash(), rpID,
		allowListOf(stale1, stale2, valid), nil)
	require.NoError(t, err, "assertion must succeed over the stale entries")
	require.NotNil(t, resp.Credential)
	require.Equal(t, valid, resp.Credential.ID,
		"the valid credential behind the stale entries must be used")
	require.Zero(t, resp.NumberOfCredentials,
		"only one credential is usable, so numberOfCredentials must be omitted")
}

// TestGetAssertion_AllowListAllStale verifies the unchanged spec behavior:
// when NO allowList entry is loadable the ceremony fails with
// CTAP2_ERR_NO_CREDENTIALS.
func TestGetAssertion_AllowListAllStale(t *testing.T) {
	rpID := "localhost"
	auth := newAllowListIterateAuthenticator(t, newSoftwareKeyBackend(t))

	stale1 := storeStaleCredential(t, auth, rpID)
	stale2 := storeStaleCredential(t, auth, rpID)

	resp, err := auth.GetAssertion(generateTestClientDataHash(), rpID,
		allowListOf(stale1, stale2), nil)
	require.Nil(t, resp)
	require.ErrorIs(t, err, ErrNoCredentials,
		"an empty applicable set must report CTAP2_ERR_NO_CREDENTIALS")
}

// TestGetAssertion_AllowListValidFirst verifies no regression in the ordinary
// case: a loadable credential first in the allowList is used even when a stale
// entry follows it.
func TestGetAssertion_AllowListValidFirst(t *testing.T) {
	rpID := "localhost"
	auth := newAllowListIterateAuthenticator(t, newSoftwareKeyBackend(t))

	valid := registerBackendCredential(t, auth, rpID, "valid@example.com")
	stale := storeStaleCredential(t, auth, rpID)

	resp, err := auth.GetAssertion(generateTestClientDataHash(), rpID,
		allowListOf(valid, stale), nil)
	require.NoError(t, err)
	require.Equal(t, valid, resp.Credential.ID)
	require.Zero(t, resp.NumberOfCredentials)
}

// TestGetAssertion_AllowListBackendFaultAborts draws the skip/abort line: a
// LoadKey failure that is NOT the typed keybackend.ErrKeyNotFound sentinel
// means the store itself is broken, and the ceremony must surface the failure
// rather than skip the entry. Skipping would let a flaky backend silently
// shrink the applicable set — a valid credential would be reported as
// nonexistent instead of the backend fault being reported as a fault.
func TestGetAssertion_AllowListBackendFaultAborts(t *testing.T) {
	rpID := "localhost"
	inner := newSoftwareKeyBackend(t)
	faulting := &faultingLoadKeyBackend{FIDO2KeyBackend: inner}
	auth := newAllowListIterateAuthenticator(t, faulting)

	broken := registerBackendCredential(t, auth, rpID, "broken@example.com")
	valid := registerBackendCredential(t, auth, rpID, "valid@example.com")
	faulting.faultID = broken

	resp, err := auth.GetAssertion(generateTestClientDataHash(), rpID,
		allowListOf(broken, valid), nil)
	require.Nil(t, resp)
	require.Error(t, err, "a broken store must abort the ceremony")
	require.ErrorIs(t, err, ErrCryptoError,
		"a backend fault maps to a crypto error, not a skip")
	require.NotErrorIs(t, err, ErrNoCredentials,
		"a backend fault must not be misreported as CTAP2_ERR_NO_CREDENTIALS")
}

// TestGetAssertion_AllowListStaleBetweenValid verifies §6.2 ordering and the
// getNextAssertion interplay after filtering: with [validA, stale, validB] the
// assertion uses validA, numberOfCredentials reflects only the two usable
// credentials, and getNextAssertion yields validB.
func TestGetAssertion_AllowListStaleBetweenValid(t *testing.T) {
	rpID := "localhost"
	auth := newAllowListIterateAuthenticator(t, newSoftwareKeyBackend(t))

	validA := registerBackendCredential(t, auth, rpID, "a@example.com")
	stale := storeStaleCredential(t, auth, rpID)
	validB := registerBackendCredential(t, auth, rpID, "b@example.com")

	resp, err := auth.GetAssertion(generateTestClientDataHash(), rpID,
		allowListOf(validA, stale, validB), nil)
	require.NoError(t, err)
	require.Equal(t, validA, resp.Credential.ID,
		"allowList order must be preserved among the loadable credentials")
	require.Equal(t, uint(2), resp.NumberOfCredentials,
		"numberOfCredentials must count only the loadable credentials")

	// getNextAssertion must walk the filtered set, never the stale entry.
	nextBytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), nextBytes[0])

	var next map[int]interface{}
	require.NoError(t, cbor.Unmarshal(nextBytes[1:], &next))
	nextID := getCredentialIDFromResponse(next[getAssertionRespCredential])
	require.Equal(t, validB, nextID,
		"getNextAssertion must return the second loadable credential")

	// The filtered sequence is exhausted after the two usable credentials.
	exhaustedBytes, err := auth.ProcessCBOR(CmdGetNextAssertion, nil)
	require.Error(t, err)
	require.Equal(t, byte(StatusNoCredentials), exhaustedBytes[0])
}

// TestFilterLoadableCredentials_EmptyInput verifies the helper handles an
// empty candidate set without touching the backend.
func TestFilterLoadableCredentials_EmptyInput(t *testing.T) {
	auth := newAllowListIterateAuthenticator(t, newSoftwareKeyBackend(t))

	loadable, err := auth.filterLoadableCredentials(nil)
	require.NoError(t, err)
	require.Empty(t, loadable)
}
