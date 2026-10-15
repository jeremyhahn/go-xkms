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

package authenticator

import (
	"crypto"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// memberBackendTypePhone names the phone member of the composite under test.
// The phone package cannot be imported here (it imports this one), so the
// fake reuses its backend identifier.
const memberBackendTypePhone xkms.BackendType = "phone"

// uvMemberHandle is the KeyHandle a uvMemberBackend hands out.
type uvMemberHandle struct {
	credentialID []byte
	algorithm    int
	backendID    xkms.BackendType
}

func (h *uvMemberHandle) CredentialID() []byte        { return h.credentialID }
func (h *uvMemberHandle) Algorithm() int              { return h.algorithm }
func (h *uvMemberHandle) BackendID() xkms.BackendType { return h.backendID }

// uvMemberBackend is a composite member holding real ES256 keys. biometric
// makes it report that its key operations collect user presence and verify the
// user, the way the phone backend's biometric prompt does.
type uvMemberBackend struct {
	backendID xkms.BackendType
	biometric bool

	mu   sync.Mutex
	keys map[string]crypto.PrivateKey
}

func newUVMemberBackend(backendID xkms.BackendType, biometric bool) *uvMemberBackend {
	return &uvMemberBackend{backendID: backendID, biometric: biometric, keys: make(map[string]crypto.PrivateKey)}
}

func (b *uvMemberBackend) Type() xkms.BackendType { return b.backendID }

func (b *uvMemberBackend) Capabilities() keybackend.FIDO2KeyCapabilities {
	return keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms:     []int{COSEAlgES256},
		HardwareBacked:          b.biometric,
		HandlesUserPresence:     b.biometric,
		HandlesUserVerification: b.biometric,
	}
}

func (b *uvMemberBackend) HandlesUserVerificationFor(backendID xkms.BackendType) bool {
	return backendID == b.backendID && b.biometric
}

func (b *uvMemberBackend) HandlesUserPresenceFor(backendID xkms.BackendType) bool {
	return backendID == b.backendID && b.biometric
}

func (b *uvMemberBackend) GenerateCredentialKey(algorithm int, credentialID []byte) (keybackend.KeyHandle, []byte, error) {
	priv, publicKeyCOSE, err := GenerateCredentialKey(algorithm)
	if err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	b.keys[string(credentialID)] = priv
	b.mu.Unlock()
	return b.handle(credentialID, algorithm), publicKeyCOSE, nil
}

func (b *uvMemberBackend) Sign(handle keybackend.KeyHandle, algorithm int, data []byte) ([]byte, error) {
	b.mu.Lock()
	priv, ok := b.keys[string(handle.CredentialID())]
	b.mu.Unlock()
	if !ok {
		return nil, keybackend.ErrKeyNotFound
	}
	return Sign(priv, algorithm, data)
}

func (b *uvMemberBackend) LoadKey(credentialID []byte, algorithm int) (keybackend.KeyHandle, error) {
	b.mu.Lock()
	_, ok := b.keys[string(credentialID)]
	b.mu.Unlock()
	if !ok {
		return nil, keybackend.ErrKeyNotFound
	}
	return b.handle(credentialID, algorithm), nil
}

func (b *uvMemberBackend) DeleteKey(handle keybackend.KeyHandle) error {
	b.mu.Lock()
	delete(b.keys, string(handle.CredentialID()))
	b.mu.Unlock()
	return nil
}

func (b *uvMemberBackend) ExportPrivateKey(keybackend.KeyHandle) ([]byte, error) {
	return nil, keybackend.ErrExportNotSupported
}

func (b *uvMemberBackend) ImportPrivateKey([]byte, int, []byte) (keybackend.KeyHandle, error) {
	return nil, keybackend.ErrImportNotSupported
}

func (b *uvMemberBackend) Close() error { return nil }

func (b *uvMemberBackend) handle(credentialID []byte, algorithm int) keybackend.KeyHandle {
	return &uvMemberHandle{credentialID: credentialID, algorithm: algorithm, backendID: b.backendID}
}

// newMixedCompositeAuthenticator returns an authenticator, without a PIN, whose
// key backend is a composite of a software member (no presence, no
// verification) and a phone member (collects presence and verifies the user
// inside every key operation), with software as the default for new
// credentials. The returned handler counts the local presence checks.
func newMixedCompositeAuthenticator(t *testing.T) (*Authenticator, *keybackend.CompositeBackend, *countingUserPresenceHandler) {
	t.Helper()
	presence := &countingUserPresenceHandler{approve: true}
	composite := keybackend.NewCompositeBackend(xkms.BackendTypeSoftware)
	composite.Register(xkms.BackendTypeSoftware, newUVMemberBackend(xkms.BackendTypeSoftware, false))
	composite.Register(memberBackendTypePhone, newUVMemberBackend(memberBackendTypePhone, true))

	auth, err := NewAuthenticator(&Config{
		UserPresenceHandler: presence,
		Storage:             NewMemoryStorage(),
		SupportedAlgorithms: []int{COSEAlgES256},
		KeyBackend:          composite,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })
	return auth, composite, presence
}

// compositeUVMakeCredential registers a credential over CTAP and returns its
// parsed authenticator data.
func compositeUVMakeCredential(t *testing.T, auth *Authenticator) *AuthenticatorData {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("composite-uv-register"))
	req, err := cbor.Marshal(map[int]interface{}{
		makeCredentialKeyClientDataHash:   clientDataHash[:],
		makeCredentialKeyRP:               map[string]string{"id": "example.com", "name": "Example"},
		makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user-1162"), "name": "user@example.com"},
		makeCredentialKeyPubKeyCredParams: []map[string]interface{}{{"type": "public-key", "alg": COSEAlgES256}},
	})
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdMakeCredential, req)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &decoded))
	raw, ok := decoded[makeCredentialResponseKeyAuthData].([]byte)
	require.True(t, ok)
	authData, err := ParseAuthData(raw)
	require.NoError(t, err)
	require.NotEmpty(t, authData.CredentialID)
	return authData
}

// compositeUVGetAssertion asserts with credentialID over CTAP and returns the
// flags of the response's authenticator data.
func compositeUVGetAssertion(t *testing.T, auth *Authenticator, credentialID []byte) AuthDataFlags {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("composite-uv-assert"))
	req, err := cbor.Marshal(map[int]interface{}{
		getAssertionParamRPID:           "example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{"type": "public-key", "id": credentialID},
		},
	})
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdGetAssertion, req)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &decoded))
	raw, ok := decoded[getAssertionRespAuthData].([]byte)
	require.True(t, ok)
	authData, err := ParseAuthData(raw)
	require.NoError(t, err)
	return authData.Flags
}

// TestCompositeUV_FlagComesFromOwningMember is the #1162 regression. A
// composite that also holds a phone must not claim the phone's biometric for a
// credential whose key lives in the software member: the UV flag comes from
// the member that created (makeCredential) or owns (getAssertion) the key.
func TestCompositeUV_FlagComesFromOwningMember(t *testing.T) {
	auth, composite, _ := newMixedCompositeAuthenticator(t)

	software := compositeUVMakeCredential(t, auth)
	require.True(t, software.Flags.Has(FlagUP))
	require.False(t, software.Flags.Has(FlagUV),
		"a software-created credential must not claim the phone member's verification")

	composite.SetDefault(memberBackendTypePhone)
	phone := compositeUVMakeCredential(t, auth)
	require.True(t, phone.Flags.Has(FlagUV),
		"a phone-created credential carries the phone's biometric verification")

	stored, err := auth.storage.Load(software.CredentialID)
	require.NoError(t, err)
	require.Equal(t, xkms.BackendTypeSoftware, stored.BackendID)
	stored, err = auth.storage.Load(phone.CredentialID)
	require.NoError(t, err)
	require.Equal(t, memberBackendTypePhone, stored.BackendID)

	// The default no longer names the software member; its credential is
	// still asserted without a UV claim because the owner, not the default,
	// decides.
	require.False(t, compositeUVGetAssertion(t, auth, software.CredentialID).Has(FlagUV),
		"an assertion from a software-owned key must not claim verification")
	require.True(t, compositeUVGetAssertion(t, auth, phone.CredentialID).Has(FlagUV),
		"an assertion from a phone-owned key carries the phone's verification")
}

// TestCompositeUV_UnknownOwnerClaimsNothing covers the fail-closed branch: a
// credential whose owning member is unrecorded or no longer registered carries
// no backend verification claim.
func TestCompositeUV_UnknownOwnerClaimsNothing(t *testing.T) {
	auth, composite, _ := newMixedCompositeAuthenticator(t)

	require.False(t, auth.backendHandlesUserVerificationFor(""))
	require.False(t, auth.backendHandlesUserVerificationFor(xkms.BackendTypeTPM2))
	require.True(t, auth.backendHandlesUserVerificationFor(memberBackendTypePhone))

	composite.Unregister(memberBackendTypePhone)
	require.False(t, auth.backendHandlesUserVerificationFor(memberBackendTypePhone))
}

// TestCompositeUV_GetInfoDoesNotAdvertiseUV checks that getInfo reads the
// composite's AND-merged capability: with a software member present, uv=true
// would promise built-in verification most credentials never get. A composite
// whose every member verifies still advertises it.
func TestCompositeUV_GetInfoDoesNotAdvertiseUV(t *testing.T) {
	options := func(t *testing.T, auth *Authenticator) map[interface{}]interface{} {
		t.Helper()
		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
		var info map[int]interface{}
		require.NoError(t, cbor.Unmarshal(resp[1:], &info))
		opts, ok := info[getInfoKeyOptions].(map[interface{}]interface{})
		require.True(t, ok)
		return opts
	}

	auth, composite, _ := newMixedCompositeAuthenticator(t)

	opts := options(t, auth)
	_, hasUV := opts["uv"]
	require.False(t, hasUV, "a mixed composite must not advertise built-in uv")
	require.Equal(t, true, opts["makeCredUvNotRqd"],
		"UV is not available for every credential, so makeCredential cannot require it")

	// getInfo carries no presence claim: "up" is left at its default (true),
	// because the authenticator can always run its own presence check, and
	// the per-credential presence routing does not change that.
	_, hasUP := opts["up"]
	require.False(t, hasUP)

	composite.Unregister(xkms.BackendTypeSoftware)
	opts = options(t, auth)
	require.Equal(t, true, opts["uv"], "a composite of verifying members advertises built-in uv")
	_, hasNotRqd := opts["makeCredUvNotRqd"]
	require.False(t, hasNotRqd)
	_, hasUP = opts["up"]
	require.False(t, hasUP)
}

// TestCompositeUP_LocalCheckUnlessOwnerCollectsPresence is the presence half
// of #1162. The composite used to OR-merge HandlesUserPresence, so a
// composite holding a phone skipped the local presence check, and still set
// UP, for software and TPM credentials. getAssertion now skips the local check
// only when the member owning the credential collects presence itself.
// makeCredential decides before the key exists, so in a mixed composite it
// always runs the local check; only a composite whose every member collects
// presence skips it.
func TestCompositeUP_LocalCheckUnlessOwnerCollectsPresence(t *testing.T) {
	auth, composite, presence := newMixedCompositeAuthenticator(t)

	software := compositeUVMakeCredential(t, auth)
	require.Equal(t, 1, presence.calls(), "a software registration runs the local presence check")
	require.True(t, software.Flags.Has(FlagUP))

	composite.SetDefault(memberBackendTypePhone)
	phone := compositeUVMakeCredential(t, auth)
	require.Equal(t, 2, presence.calls(),
		"the creating member is unknown before key generation, so a mixed composite runs the local check")
	require.True(t, phone.Flags.Has(FlagUP))

	flags := compositeUVGetAssertion(t, auth, software.CredentialID)
	require.Equal(t, 3, presence.calls(),
		"an assertion from a software-owned key runs the local presence check")
	require.True(t, flags.Has(FlagUP))

	flags = compositeUVGetAssertion(t, auth, phone.CredentialID)
	require.Equal(t, 3, presence.calls(),
		"an assertion from a phone-owned key relies on the phone's biometric prompt")
	require.True(t, flags.Has(FlagUP))

	composite.Unregister(xkms.BackendTypeSoftware)
	compositeUVMakeCredential(t, auth)
	require.Equal(t, 3, presence.calls(),
		"a composite whose every member collects presence skips the local check")
}

// TestCompositeUP_UnknownOwnerRunsLocalCheck covers the fail-closed branch: a
// credential whose owning member is unrecorded or no longer registered never
// skips the local presence check.
func TestCompositeUP_UnknownOwnerRunsLocalCheck(t *testing.T) {
	auth, composite, _ := newMixedCompositeAuthenticator(t)

	require.False(t, auth.backendHandlesUserPresence(), "a mixed composite does not collect presence everywhere")
	require.False(t, auth.backendHandlesUserPresenceFor(""))
	require.False(t, auth.backendHandlesUserPresenceFor(xkms.BackendTypeSoftware))
	require.False(t, auth.backendHandlesUserPresenceFor(xkms.BackendTypeTPM2))
	require.True(t, auth.backendHandlesUserPresenceFor(memberBackendTypePhone))

	composite.Unregister(memberBackendTypePhone)
	require.False(t, auth.backendHandlesUserPresenceFor(memberBackendTypePhone))
}
