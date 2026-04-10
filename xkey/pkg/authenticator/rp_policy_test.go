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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestRPPolicyValidate verifies RPPolicy.Validate() accepts valid policies
// and rejects invalid ones with the correct typed errors.
func TestRPPolicyValidate(t *testing.T) {
	t.Run("valid policy with all defaults", func(t *testing.T) {
		policy := &RPPolicy{RPID: "example.com"}
		err := policy.Validate()
		require.NoError(t, err)
	})

	t.Run("valid policy with all fields set", func(t *testing.T) {
		upFalse := false
		policy := &RPPolicy{
			RPID:                "corp.example.com",
			UVOverride:          "required",
			UPOverride:          &upFalse,
			AttestationOverride: "direct",
			Enterprise:          true,
			Blocked:             false,
		}
		err := policy.Validate()
		require.NoError(t, err)
	})

	t.Run("valid UV override values", func(t *testing.T) {
		for _, uv := range []string{"", "required", "preferred", "discouraged"} {
			policy := &RPPolicy{RPID: "example.com", UVOverride: uv}
			err := policy.Validate()
			require.NoError(t, err, "UVOverride=%q should be valid", uv)
		}
	})

	t.Run("valid attestation override values", func(t *testing.T) {
		for _, att := range []string{"", "none", "indirect", "direct", "enterprise"} {
			policy := &RPPolicy{RPID: "example.com", AttestationOverride: att}
			err := policy.Validate()
			require.NoError(t, err, "AttestationOverride=%q should be valid", att)
		}
	})

	t.Run("nil policy returns ErrRPPolicyNil", func(t *testing.T) {
		var policy *RPPolicy
		err := policy.Validate()
		require.ErrorIs(t, err, ErrRPPolicyNil)
	})

	t.Run("empty RPID returns ErrRPPolicyInvalidRPID", func(t *testing.T) {
		policy := &RPPolicy{RPID: ""}
		err := policy.Validate()
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("invalid UV override returns ErrInvalidParameter", func(t *testing.T) {
		policy := &RPPolicy{RPID: "example.com", UVOverride: "bogus"}
		err := policy.Validate()
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("invalid attestation override returns ErrInvalidParameter", func(t *testing.T) {
		policy := &RPPolicy{RPID: "example.com", AttestationOverride: "self-signed"}
		err := policy.Validate()
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

// TestMemoryRPPolicyStore verifies CRUD operations on the in-memory RP policy store.
func TestMemoryRPPolicyStore(t *testing.T) {
	t.Run("set and get policy", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		policy := &RPPolicy{
			RPID:       "example.com",
			UVOverride: "required",
			Enterprise: true,
		}
		err := store.SetPolicy(policy)
		require.NoError(t, err)

		got, err := store.GetPolicy("example.com")
		require.NoError(t, err)
		require.Equal(t, "example.com", got.RPID)
		require.Equal(t, "required", got.UVOverride)
		require.True(t, got.Enterprise)
	})

	t.Run("get returns deep copy", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		upTrue := true
		policy := &RPPolicy{
			RPID:       "example.com",
			UPOverride: &upTrue,
		}
		err := store.SetPolicy(policy)
		require.NoError(t, err)

		got, err := store.GetPolicy("example.com")
		require.NoError(t, err)

		// Mutate the returned copy; the stored value should not change
		*got.UPOverride = false

		got2, err := store.GetPolicy("example.com")
		require.NoError(t, err)
		require.True(t, *got2.UPOverride, "mutating returned policy must not affect stored value")
	})

	t.Run("set overwrites existing policy", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.SetPolicy(&RPPolicy{RPID: "example.com", UVOverride: "required"})
		require.NoError(t, err)

		err = store.SetPolicy(&RPPolicy{RPID: "example.com", UVOverride: "discouraged"})
		require.NoError(t, err)

		got, err := store.GetPolicy("example.com")
		require.NoError(t, err)
		require.Equal(t, "discouraged", got.UVOverride)
	})

	t.Run("get nonexistent policy returns ErrRPPolicyNotFound", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		_, err := store.GetPolicy("nonexistent.com")
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("get with empty RPID returns ErrRPPolicyInvalidRPID", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		_, err := store.GetPolicy("")
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("set with invalid policy returns validation error", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.SetPolicy(&RPPolicy{RPID: ""})
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)

		err = store.SetPolicy(nil)
		require.ErrorIs(t, err, ErrRPPolicyNil)
	})

	t.Run("delete policy", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.SetPolicy(&RPPolicy{RPID: "example.com"})
		require.NoError(t, err)

		err = store.DeletePolicy("example.com")
		require.NoError(t, err)

		_, err = store.GetPolicy("example.com")
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("delete nonexistent policy returns ErrRPPolicyNotFound", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.DeletePolicy("nonexistent.com")
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("delete with empty RPID returns ErrRPPolicyInvalidRPID", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.DeletePolicy("")
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("list policies", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.SetPolicy(&RPPolicy{RPID: "a.com"})
		require.NoError(t, err)
		err = store.SetPolicy(&RPPolicy{RPID: "b.com", Blocked: true})
		require.NoError(t, err)

		policies, err := store.ListPolicies()
		require.NoError(t, err)
		require.Len(t, policies, 2)

		// Verify both RPs are present (order is non-deterministic in maps)
		rpIDs := map[string]bool{}
		for _, p := range policies {
			rpIDs[p.RPID] = true
		}
		require.True(t, rpIDs["a.com"])
		require.True(t, rpIDs["b.com"])
	})

	t.Run("list empty store", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		policies, err := store.ListPolicies()
		require.NoError(t, err)
		require.Empty(t, policies)
	})
}

// TestMemoryRPPolicyStoreClose verifies that all operations return
// ErrRPPolicyStoreClosed after the store is closed.
func TestMemoryRPPolicyStoreClose(t *testing.T) {
	t.Run("operations on closed store return ErrRPPolicyStoreClosed", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		// Seed a policy before closing
		err := store.SetPolicy(&RPPolicy{RPID: "example.com"})
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)

		// All operations should now fail
		err = store.SetPolicy(&RPPolicy{RPID: "other.com"})
		require.ErrorIs(t, err, ErrRPPolicyStoreClosed)

		_, err = store.GetPolicy("example.com")
		require.ErrorIs(t, err, ErrRPPolicyStoreClosed)

		err = store.DeletePolicy("example.com")
		require.ErrorIs(t, err, ErrRPPolicyStoreClosed)

		_, err = store.ListPolicies()
		require.ErrorIs(t, err, ErrRPPolicyStoreClosed)
	})

	t.Run("double close is idempotent", func(t *testing.T) {
		store := NewMemoryRPPolicyStore()

		err := store.Close()
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	})
}

// TestRPPolicyBlockedMakeCredential verifies that MakeCredential returns
// ErrRPBlocked when the RP is blocked by SO policy.
func TestRPPolicyBlockedMakeCredential(t *testing.T) {
	storage := NewMemoryStorage()
	policyStore := NewMemoryRPPolicyStore()

	config := DefaultConfig()
	config.Storage = storage
	config.RPPolicyStore = policyStore
	// Disable PIN so we can test without providing pinUvAuthParam
	config.EnablePIN = false
	config.EnableCredentialManagement = false

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	// Block example.com
	err = policyStore.SetPolicy(&RPPolicy{
		RPID:    "example.com",
		Blocked: true,
	})
	require.NoError(t, err)

	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("blocked RP returns ErrRPBlocked via HandleMakeCredential", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "example.com",
				"name": "Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-1"),
				"name":        "test@example.com",
				"displayName": "Test User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData, cborErr := cbor.Marshal(reqMap)
		require.NoError(t, cborErr)

		_, err := auth.HandleMakeCredential(reqData)
		require.ErrorIs(t, err, ErrRPBlocked)
	})

	t.Run("non-blocked RP succeeds", func(t *testing.T) {
		reqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "allowed.com",
				"name": "Allowed",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-2"),
				"name":        "test@allowed.com",
				"displayName": "Test User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}

		reqData, cborErr := cbor.Marshal(reqMap)
		require.NoError(t, cborErr)

		resp, err := auth.HandleMakeCredential(reqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
	})
}

// TestRPPolicyBlockedGetAssertion verifies that GetAssertion returns
// ErrRPBlocked when the RP is blocked after a credential was created.
func TestRPPolicyBlockedGetAssertion(t *testing.T) {
	storage := NewMemoryStorage()
	policyStore := NewMemoryRPPolicyStore()

	config := DefaultConfig()
	config.Storage = storage
	config.RPPolicyStore = policyStore
	config.EnablePIN = false
	config.EnableCredentialManagement = false

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	// Create a credential first (RP not blocked yet)
	makeReqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "example.com",
			"name": "Example",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-1"),
			"name":        "test@example.com",
			"displayName": "Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
	}
	makeReqData, err := cbor.Marshal(makeReqMap)
	require.NoError(t, err)

	makeResp, err := auth.HandleMakeCredential(makeReqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeResp[0])

	// Parse credential ID from MakeCredential response
	var makeRespMap map[int]interface{}
	err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
	require.NoError(t, err)

	authDataBytes, ok := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
	require.True(t, ok)
	authData, err := ParseAuthData(authDataBytes)
	require.NoError(t, err)
	credentialID := authData.CredentialID

	// Now block the RP
	err = policyStore.SetPolicy(&RPPolicy{
		RPID:    "example.com",
		Blocked: true,
	})
	require.NoError(t, err)

	t.Run("blocked RP returns ErrRPBlocked", func(t *testing.T) {
		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}

		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.ErrorIs(t, err, ErrRPBlocked)
	})

	t.Run("unblocking RP restores access", func(t *testing.T) {
		// Remove the block
		err := policyStore.DeletePolicy("example.com")
		require.NoError(t, err)

		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}

		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
	})
}

// rejectingUPHandler immediately returns ErrUserPresenceRequired instead
// of blocking. Used to prove that silent auth (UP override) correctly
// bypasses the UP check without hanging.
type rejectingUPHandler struct{}

func (h *rejectingUPHandler) RequestUserPresence(_ context.Context, _ *UserPresenceRequest) (*UserPresenceResult, error) {
	return nil, ErrUserPresenceRequired
}

func (h *rejectingUPHandler) RequestUserVerification(_ context.Context, _ *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrUserVerificationRequired
}

// Compile-time interface check.
var _ UserPresenceHandler = (*rejectingUPHandler)(nil)

// TestSilentAuthViaRPPolicy verifies that GetAssertion succeeds without
// user presence interaction when the RP policy sets UPOverride=false.
func TestSilentAuthViaRPPolicy(t *testing.T) {
	storage := NewMemoryStorage()
	policyStore := NewMemoryRPPolicyStore()

	config := DefaultConfig()
	config.Storage = storage
	config.RPPolicyStore = policyStore
	config.EnablePIN = false
	config.EnableCredentialManagement = false
	// Use a handler that rejects UP requests, proving UP is skipped
	config.UserPresenceHandler = &rejectingUPHandler{}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	// Create a credential with auto-grant UP for MakeCredential since the
	// rejecting handler would prevent credential creation; temporarily swap it
	auth.upHandler = NewAutoGrantHandler()
	makeReqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "silent.example.com",
			"name": "Silent Example",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-silent"),
			"name":        "silent@example.com",
			"displayName": "Silent User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
	}
	makeReqData, err := cbor.Marshal(makeReqMap)
	require.NoError(t, err)

	makeResp, err := auth.HandleMakeCredential(makeReqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeResp[0])

	var makeRespMap map[int]interface{}
	err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
	require.NoError(t, err)
	authDataBytes := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
	parsedAuthData, err := ParseAuthData(authDataBytes)
	require.NoError(t, err)
	credentialID := parsedAuthData.CredentialID

	// Restore the rejecting handler and set silent auth policy
	auth.upHandler = &rejectingUPHandler{}

	upFalse := false
	err = policyStore.SetPolicy(&RPPolicy{
		RPID:       "silent.example.com",
		UPOverride: &upFalse,
	})
	require.NoError(t, err)

	t.Run("silent auth succeeds without UP prompt", func(t *testing.T) {
		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "silent.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}

		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		// If the rejecting handler were invoked, this would return
		// ErrUserPresenceRequired. Success means the SO policy correctly
		// suppressed the UP prompt.
		resp, err := auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
	})
}

// TestRPPolicyUVDiscouragedSkipsPIN verifies that GetAssertion skips PIN
// requirement when the RP policy sets UVOverride="discouraged", even when
// PIN is configured and set.
func TestRPPolicyUVDiscouragedSkipsPIN(t *testing.T) {
	storage := NewMemoryStorage()
	policyStore := NewMemoryRPPolicyStore()

	// Pre-seed state with PIN set
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage
	config.RPPolicyStore = policyStore
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	// Create a credential using valid pinUvAuthParam so MakeCredential succeeds
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential | PINPermissionGetAssertion,
	}

	mac := hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	makeReqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "uvskip.example.com",
			"name": "UV Skip Example",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-uvskip"),
			"name":        "uvskip@example.com",
			"displayName": "UV Skip User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
		makeCredentialKeyPINUVAuthParam:    pinUvAuthParam,
		makeCredentialKeyPINUVAuthProtocol: uint8(1),
	}
	makeReqData, err := cbor.Marshal(makeReqMap)
	require.NoError(t, err)

	makeResp, err := auth.HandleMakeCredential(makeReqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeResp[0])

	var makeRespMap map[int]interface{}
	err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
	require.NoError(t, err)
	authDataBytes := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
	parsedAuthData, err := ParseAuthData(authDataBytes)
	require.NoError(t, err)
	credentialID := parsedAuthData.CredentialID

	// Clear the PIN token so GetAssertion has no valid pinUvAuthParam
	auth.pinState.protocol = nil

	// Set UV discouraged policy for this RP
	err = policyStore.SetPolicy(&RPPolicy{
		RPID:       "uvskip.example.com",
		UVOverride: "discouraged",
	})
	require.NoError(t, err)

	t.Run("GetAssertion succeeds without PIN when UV is discouraged by policy", func(t *testing.T) {
		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "uvskip.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}

		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
	})

	t.Run("GetAssertion requires PIN for RP without UV discouraged policy", func(t *testing.T) {
		// Create credential for different RP using PIN auth
		pinToken2 := make([]byte, 32)
		for i := range pinToken2 {
			pinToken2[i] = byte(i + 10)
		}
		auth.pinState.protocol = &pinProtocolState{
			pinUvAuthToken:   pinToken2,
			tokenPermissions: PINPermissionMakeCredential | PINPermissionGetAssertion,
		}

		mac2 := hmac.New(sha256.New, pinToken2)
		mac2.Write(clientDataHash)
		pinUvAuthParam2 := mac2.Sum(nil)[:16]

		makeReqMap2 := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "nopolicy.example.com",
				"name": "No Policy Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-nopolicy"),
				"name":        "nopolicy@example.com",
				"displayName": "No Policy User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyPINUVAuthParam:    pinUvAuthParam2,
			makeCredentialKeyPINUVAuthProtocol: uint8(1),
		}
		makeReqData2, err := cbor.Marshal(makeReqMap2)
		require.NoError(t, err)

		makeResp2, err := auth.HandleMakeCredential(makeReqData2)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), makeResp2[0])

		var makeRespMap2 map[int]interface{}
		err = cbor.Unmarshal(makeResp2[1:], &makeRespMap2)
		require.NoError(t, err)
		authDataBytes2 := makeRespMap2[makeCredentialResponseKeyAuthData].([]byte)
		parsedAuthData2, err := ParseAuthData(authDataBytes2)
		require.NoError(t, err)
		credentialID2 := parsedAuthData2.CredentialID

		// Clear PIN token again
		auth.pinState.protocol = nil

		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "nopolicy.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID2,
				},
			},
			getAssertionParamOptions: map[string]bool{
				"up": true,
				"uv": true,
			},
		}

		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		// With uv=true and no UV discouraged policy, this should require PIN
		_, err = auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.ErrorIs(t, err, ErrPINRequired)
	})
}

// TestStoredCredentialRPFields verifies that MakeCredential stores
// the derived RP policy fields (RPUVPolicy, RPUPPolicy, RPResidentKeyPolicy)
// on the credential.
func TestStoredCredentialRPFields(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = false
	config.EnableCredentialManagement = false

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	t.Run("default options store discouraged UV and true UP", func(t *testing.T) {
		makeReqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "fields.example.com",
				"name": "Fields Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-fields"),
				"name":        "fields@example.com",
				"displayName": "Fields User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
		}
		makeReqData, err := cbor.Marshal(makeReqMap)
		require.NoError(t, err)

		makeResp, err := auth.HandleMakeCredential(makeReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), makeResp[0])

		var makeRespMap map[int]interface{}
		err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
		require.NoError(t, err)
		authDataBytes := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
		parsedAuthData, err := ParseAuthData(authDataBytes)
		require.NoError(t, err)

		cred, err := auth.storage.Load(parsedAuthData.CredentialID)
		require.NoError(t, err)
		require.Equal(t, "discouraged", cred.RPUVPolicy)
		require.True(t, cred.RPUPPolicy)
		require.Equal(t, "", cred.RPResidentKeyPolicy)
	})

	t.Run("rk=true stores required resident key policy", func(t *testing.T) {
		makeReqMap := map[int]interface{}{
			makeCredentialKeyClientDataHash: clientDataHash,
			makeCredentialKeyRP: map[string]interface{}{
				"id":   "rk.example.com",
				"name": "RK Example",
			},
			makeCredentialKeyUser: map[string]interface{}{
				"id":          []byte("user-rk"),
				"name":        "rk@example.com",
				"displayName": "RK User",
			},
			makeCredentialKeyPubKeyCredParams: []interface{}{
				map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
			},
			makeCredentialKeyOptions: map[string]interface{}{
				"rk": true,
			},
		}
		makeReqData, err := cbor.Marshal(makeReqMap)
		require.NoError(t, err)

		makeResp, err := auth.HandleMakeCredential(makeReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), makeResp[0])

		var makeRespMap map[int]interface{}
		err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
		require.NoError(t, err)
		authDataBytes := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
		parsedAuthData, err := ParseAuthData(authDataBytes)
		require.NoError(t, err)

		cred, err := auth.storage.Load(parsedAuthData.CredentialID)
		require.NoError(t, err)
		require.Equal(t, "required", cred.RPResidentKeyPolicy)
	})
}

// TestGetAssertionSkipsPINWhenUVNotRequested verifies that GetAssertion
// does NOT require PIN when the current request omits uv=true, even when the
// credential was originally created with uv=true (RPUVPolicy="required").
// This matches CTAP2 spec §6.2.2 and YubiKey-like behavior: the authenticator
// follows the current request's UV option rather than a stored creation-time
// policy. Chrome escalates WebAuthn "preferred" to CTAP2 uv=true during
// MakeCredential, so enforcing the stored policy would force PIN on every
// "preferred" assertion.
func TestGetAssertionSkipsPINWhenUVNotRequested(t *testing.T) {
	storage := NewMemoryStorage()

	// Pre-seed state with PIN set.
	state := NewAuthenticatorState()
	state.AAGUID = DefaultAAGUID
	state.PINSet = true
	err := storage.SaveState(state)
	require.NoError(t, err)

	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.AlwaysUV = false
	// Auto-approve user presence so the test doesn't block.
	config.RequireUserPresence = false

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	clientDataHash := make([]byte, ClientDataHashSize)

	// Set up PIN token for MakeCredential.
	pinToken := make([]byte, 32)
	for i := range pinToken {
		pinToken[i] = byte(i + 50)
	}
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   pinToken,
		tokenPermissions: PINPermissionMakeCredential | PINPermissionGetAssertion,
	}

	mac := hmac.New(sha256.New, pinToken)
	mac.Write(clientDataHash)
	pinUvAuthParam := mac.Sum(nil)[:16]

	// Create credential with uv=true (Chrome sends this for "preferred").
	makeReqMap := map[int]interface{}{
		makeCredentialKeyClientDataHash: clientDataHash,
		makeCredentialKeyRP: map[string]interface{}{
			"id":   "uvtest.example.com",
			"name": "UV Test",
		},
		makeCredentialKeyUser: map[string]interface{}{
			"id":          []byte("user-uvtest"),
			"name":        "uvtest@example.com",
			"displayName": "UV Test User",
		},
		makeCredentialKeyPubKeyCredParams: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": COSEAlgES256},
		},
		makeCredentialKeyOptions: map[string]bool{
			"uv": true,
		},
		makeCredentialKeyPINUVAuthParam:    pinUvAuthParam,
		makeCredentialKeyPINUVAuthProtocol: uint8(1),
	}
	makeReqData, err := cbor.Marshal(makeReqMap)
	require.NoError(t, err)

	makeResp, err := auth.HandleMakeCredential(makeReqData)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), makeResp[0])

	// Verify the credential stored RPUVPolicy="required".
	var makeRespMap map[int]interface{}
	err = cbor.Unmarshal(makeResp[1:], &makeRespMap)
	require.NoError(t, err)
	authDataBytes := makeRespMap[makeCredentialResponseKeyAuthData].([]byte)
	parsedAuthData, err := ParseAuthData(authDataBytes)
	require.NoError(t, err)
	credentialID := parsedAuthData.CredentialID

	cred, err := storage.Load(credentialID)
	require.NoError(t, err)
	require.Equal(t, "required", cred.RPUVPolicy,
		"credential should store RPUVPolicy=required when created with uv=true")

	// Clear PIN token so GetAssertion has no pinUvAuthParam.
	auth.pinState.protocol = nil

	t.Run("no uv option succeeds without PIN", func(t *testing.T) {
		// GetAssertion without uv=true should succeed with just touch,
		// matching YubiKey behavior for userVerification: "preferred".
		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "uvtest.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}
		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		resp, err := auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
	})

	t.Run("explicit uv=true still requires PIN", func(t *testing.T) {
		// GetAssertion WITH uv=true should still require PIN per spec.
		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "uvtest.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
			getAssertionParamOptions: map[string]bool{
				"uv": true,
			},
		}
		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.ErrorIs(t, err, ErrPINRequired)
	})

	t.Run("alwaysUV forces PIN regardless", func(t *testing.T) {
		auth.config.AlwaysUV = true
		defer func() { auth.config.AlwaysUV = false }()

		getReqMap := map[int]interface{}{
			getAssertionParamRPID:           "uvtest.example.com",
			getAssertionParamClientDataHash: clientDataHash,
			getAssertionParamAllowList: []interface{}{
				map[string]interface{}{
					"type": "public-key",
					"id":   credentialID,
				},
			},
		}
		getReqData, err := cbor.Marshal(getReqMap)
		require.NoError(t, err)

		_, err = auth.ProcessCBOR(CmdGetAssertion, getReqData)
		require.ErrorIs(t, err, ErrPINRequired)
	})
}

// TestGetInfoConfigurableTransports verifies that custom Transports from
// the Config appear in the GetInfo response.
func TestGetInfoConfigurableTransports(t *testing.T) {
	t.Run("custom transports in GetInfo", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.Transports = []string{"internal", "hybrid"}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		transports, ok := respMap[getInfoKeyTransports].([]interface{})
		require.True(t, ok)
		require.Len(t, transports, 2)
		require.Equal(t, "internal", transports[0])
		require.Equal(t, "hybrid", transports[1])
	})

	t.Run("default transports is usb", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		// No custom transports set

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		transports, ok := respMap[getInfoKeyTransports].([]interface{})
		require.True(t, ok)
		require.Len(t, transports, 1)
		require.Equal(t, "usb", transports[0])
	})
}

// TestGetInfoAlwaysUVOption verifies that the alwaysUv option appears in
// GetInfo options when AlwaysUV is enabled in the config.
func TestGetInfoAlwaysUVOption(t *testing.T) {
	t.Run("alwaysUv present when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.AlwaysUV = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		options, ok := respMap[getInfoKeyOptions]
		require.True(t, ok)

		optionsMap := rpPolicyCborMapToBoolMap(t, options)
		alwaysUv, exists := optionsMap["alwaysUv"]
		require.True(t, exists, "alwaysUv option must be present in GetInfo")
		require.True(t, alwaysUv)
	})

	t.Run("alwaysUv absent when disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.AlwaysUV = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		options, ok := respMap[getInfoKeyOptions]
		require.True(t, ok)

		optionsMap := rpPolicyCborMapToBoolMap(t, options)
		_, exists := optionsMap["alwaysUv"]
		require.False(t, exists, "alwaysUv option should be absent when disabled (default per spec)")
	})
}

// TestGetInfoEnterpriseAttestationOption verifies that the ep option appears
// in GetInfo options when EnableEnterpriseAttestation is enabled.
func TestGetInfoEnterpriseAttestationOption(t *testing.T) {
	t.Run("ep present when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableEnterpriseAttestation = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		options, ok := respMap[getInfoKeyOptions]
		require.True(t, ok)

		optionsMap := rpPolicyCborMapToBoolMap(t, options)
		ep, exists := optionsMap["ep"]
		require.True(t, exists, "ep option must be present in GetInfo when enterprise attestation is enabled")
		require.True(t, ep)
	})

	t.Run("ep absent when disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableEnterpriseAttestation = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		options, ok := respMap[getInfoKeyOptions]
		require.True(t, ok)

		optionsMap := rpPolicyCborMapToBoolMap(t, options)
		_, exists := optionsMap["ep"]
		require.False(t, exists, "ep option should be absent when enterprise attestation is disabled")
	})
}

// TestGetInfoLargeBlobExtension verifies that the largeBlobKey extension
// appears in GetInfo extensions when EnableLargeBlobs is enabled.
func TestGetInfoLargeBlobExtension(t *testing.T) {
	t.Run("largeBlobKey in extensions when enabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableLargeBlobs = true

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		extensions, ok := respMap[getInfoKeyExtensions].([]interface{})
		require.True(t, ok, "extensions should be present in GetInfo response")

		found := false
		for _, ext := range extensions {
			if ext == "largeBlobKey" {
				found = true
				break
			}
		}
		require.True(t, found, "largeBlobKey must be in extensions list when EnableLargeBlobs=true")
	})

	t.Run("largeBlobKey absent when disabled", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		config.EnableLargeBlobs = false

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		defer func() { _ = auth.Close() }()

		resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(resp[1:], &respMap)
		require.NoError(t, err)

		extensions, ok := respMap[getInfoKeyExtensions].([]interface{})
		require.True(t, ok)

		for _, ext := range extensions {
			require.NotEqual(t, "largeBlobKey", ext,
				"largeBlobKey should not appear in extensions when EnableLargeBlobs=false")
		}
	})
}

// rpPolicyCborMapToBoolMap converts a CBOR-decoded options map (which may use
// interface{} keys) to a Go map[string]bool for easier assertions.
func rpPolicyCborMapToBoolMap(t *testing.T, raw interface{}) map[string]bool {
	t.Helper()
	result := make(map[string]bool)

	switch m := raw.(type) {
	case map[interface{}]interface{}:
		for k, v := range m {
			key, ok := k.(string)
			if !ok {
				continue
			}
			val, ok := v.(bool)
			if !ok {
				continue
			}
			result[key] = val
		}
	case map[string]interface{}:
		for k, v := range m {
			val, ok := v.(bool)
			if !ok {
				continue
			}
			result[k] = val
		}
	default:
		t.Fatalf("unexpected options map type: %T", raw)
	}

	return result
}
