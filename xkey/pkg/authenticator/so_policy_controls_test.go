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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// This file proves the two Security-Officer controls from #216 that this
// change makes fire: the "enterprise" attestation override requires the RP's
// entitlement, and a tampered policy locks user-mode operations.

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// newPackedPolicyAuth builds an authenticator that can produce a packed
// attestation statement and consults an RP policy store, so an override that
// asks for attestation has something real to resolve to.
func newPackedPolicyAuth(t *testing.T, enterprise bool) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		UserPresenceHandler:         NewAutoGrantHandler(),
		Storage:                     NewMemoryStorage(),
		RPPolicyStore:               NewMemoryRPPolicyStore(),
		SupportedAlgorithms:         []int{COSEAlgES256},
		MaxCredentials:              100,
		MaxResidentCredentials:      25,
		PINMinLength:                4,
		PINMaxRetries:               8,
		AttestationFormat:           AttestationFormatPacked,
		EnableEnterpriseAttestation: enterprise,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	provisionAttestation(t, auth, newTestAttestationCA(t, false))
	return auth
}

// registerUnderPolicy runs a Go API registration for the RP the policy names.
func registerUnderPolicy(t *testing.T, auth *Authenticator, policy *RPPolicy) (*MakeCredentialResponse, error) {
	t.Helper()
	require.NoError(t, auth.rpPolicyStore.SetPolicy(policy))
	return auth.MakeCredential(protectCDH(),
		RelyingParty{ID: policy.RPID, Name: policy.RPID}, protectUser(), protectParams(), nil)
}

// newTamperedAuth signs a policy, saves it, then re-opens the same storage
// under a changed configuration so startup verification reports tampering.
// It returns the tampered authenticator along with the storage and provider
// so a test can exercise the SO recovery path.
func newTamperedAuth(t *testing.T) (*Authenticator, *MemoryStorage, PolicyIntegrityProvider) {
	t.Helper()
	provider, err := NewSoftwarePolicyProvider(testPolicyKey(t))
	require.NoError(t, err)
	storage := NewMemoryStorage()

	signed := newPolicyAuth(t, storage, provider, DefaultConfig().PINMinLength)
	require.NoError(t, signed.PolicyManager().Sign(signed.state))
	require.NoError(t, storage.SaveState(signed.state))
	require.NoError(t, signed.Close())

	tampered := newPolicyAuth(t, storage, provider, 12)
	require.True(t, tampered.TamperDetected.Load(), "fixture must start tamper-detected")
	return tampered, storage, provider
}

// newPolicyAuth opens an authenticator over shared storage with a policy
// integrity provider and the given minimum PIN length, which is the field the
// tamper fixture flips.
func newPolicyAuth(t *testing.T, storage *MemoryStorage, provider PolicyIntegrityProvider, pinMinLength int) *Authenticator {
	t.Helper()
	cfg := DefaultConfig()
	cfg.UserPresenceHandler = NewAutoGrantHandler()
	cfg.Storage = storage
	cfg.PolicyIntegrityProvider = provider
	cfg.PINMinLength = pinMinLength
	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// completeMakeCredentialCBOR encodes a makeCredential request that decodes and
// validates cleanly, so a refusal can only come from a gate in front of it.
func completeMakeCredentialCBOR(t *testing.T) []byte {
	t.Helper()
	data, err := cbor.Marshal(map[int]interface{}{
		makeCredentialKeyClientDataHash:   protectCDH(),
		makeCredentialKeyRP:               map[string]string{"id": "example.com", "name": "Example"},
		makeCredentialKeyUser:             map[string]interface{}{"id": []byte("user-id"), "name": "user", "displayName": "User"},
		makeCredentialKeyPubKeyCredParams: []map[string]interface{}{{"type": "public-key", "alg": COSEAlgES256}},
	})
	require.NoError(t, err)
	return data
}

// --------------------------------------------------------------------------
// D — attestation override vocabulary and the enterprise entitlement
// --------------------------------------------------------------------------

// TestAttestationOverrideDirectProducesConfiguredFormat proves the preference
// vocabulary translates to the configured statement format: an SO who sets
// "direct" gets a packed statement, never fmt=none.
func TestAttestationOverrideDirectProducesConfiguredFormat(t *testing.T) {
	auth := newPackedPolicyAuth(t, false)

	for _, preference := range []string{AttestationConveyanceDirect, AttestationConveyanceIndirect} {
		resp, err := registerUnderPolicy(t, auth, &RPPolicy{
			RPID:                preference + ".example",
			AttestationOverride: preference,
		})
		require.NoError(t, err, preference)
		require.Equal(t, AttestationFormatPacked, resp.Fmt,
			"preference %q must resolve to the configured statement format", preference)
		require.NotEmpty(t, resp.AttStmt["x5c"], "a packed statement must carry its chain")
	}
}

// TestAttestationOverrideEnterpriseEntitledProducesStatement proves the happy
// path of the entitlement check: enterprise enabled and the RP marked
// Enterprise resolves to the configured format.
func TestAttestationOverrideEnterpriseEntitledProducesStatement(t *testing.T) {
	auth := newPackedPolicyAuth(t, true)

	resp, err := registerUnderPolicy(t, auth, &RPPolicy{
		RPID:                "entitled.example",
		AttestationOverride: AttestationConveyanceEnterprise,
		Enterprise:          true,
	})
	require.NoError(t, err)
	require.Equal(t, AttestationFormatPacked, resp.Fmt)
}

// TestAttestationOverrideEnterpriseRequiresEntitlement proves an "enterprise"
// override for an RP that is not entitled to it is refused with a typed error
// rather than resolved to the ordinary statement. Both halves of the
// entitlement are required, so each is removed in turn.
func TestAttestationOverrideEnterpriseRequiresEntitlement(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enterpriseConfig bool
		enterprisePolicy bool
	}{
		{name: "RP not marked enterprise", enterpriseConfig: true, enterprisePolicy: false},
		{name: "enterprise attestation disabled", enterpriseConfig: false, enterprisePolicy: true},
		{name: "neither", enterpriseConfig: false, enterprisePolicy: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newPackedPolicyAuth(t, tc.enterpriseConfig)
			policy := &RPPolicy{
				RPID:                "corp.example",
				AttestationOverride: AttestationConveyanceEnterprise,
				Enterprise:          tc.enterprisePolicy,
			}

			format, err := auth.resolveAttestationOverride(policy)
			require.ErrorIs(t, err, ErrEnterpriseAttestationNotEntitled)
			require.Empty(t, format)

			_, err = registerUnderPolicy(t, auth, policy)
			require.ErrorIs(t, err, ErrEnterpriseAttestationNotEntitled,
				"the refusal must reach the registration, not just the resolver")
		})
	}
}

// TestAttestationOverrideEnterpriseEntitlementBeforeFormat proves the
// entitlement is checked before the configured format, so an unentitled RP is
// told why it was refused even on an authenticator that produces no
// attestation at all.
func TestAttestationOverrideEnterpriseEntitlementBeforeFormat(t *testing.T) {
	auth := newProtectAuth(t) // AttestationFormat defaults to "none"

	_, err := auth.resolveAttestationOverride(&RPPolicy{
		RPID:                "corp.example",
		AttestationOverride: AttestationConveyanceEnterprise,
	})
	require.ErrorIs(t, err, ErrEnterpriseAttestationNotEntitled)
}

// TestConfiguredAttestationFormat covers the shared helper both branches use.
func TestConfiguredAttestationFormat(t *testing.T) {
	packed := newPackedPolicyAuth(t, false)
	format, err := packed.configuredAttestationFormat()
	require.NoError(t, err)
	require.Equal(t, AttestationFormatPacked, format)

	none := newProtectAuth(t)
	format, err = none.configuredAttestationFormat()
	require.ErrorIs(t, err, ErrAttestationOverrideUnsupported)
	require.Empty(t, format)
}

// TestEnterpriseNotEntitledMapsToOperationDenied pins the CTAP status a
// platform sees for the refusal.
func TestEnterpriseNotEntitledMapsToOperationDenied(t *testing.T) {
	require.Equal(t, byte(StatusOperationDenied), errorToStatus(ErrEnterpriseAttestationNotEntitled))
}

// --------------------------------------------------------------------------
// E1 — the tamper flag now locks user-mode operations
// --------------------------------------------------------------------------

// TestRequirePolicyIntegrityPassesWhenClean is the happy path of the gate: an
// authenticator whose policy verified, or that has no integrity provider at
// all, is not locked.
func TestRequirePolicyIntegrityPassesWhenClean(t *testing.T) {
	require.NoError(t, newProtectAuth(t).requirePolicyIntegrity())

	provider, err := NewSoftwarePolicyProvider(testPolicyKey(t))
	require.NoError(t, err)
	storage := NewMemoryStorage()
	signed := newPolicyAuth(t, storage, provider, DefaultConfig().PINMinLength)
	require.NoError(t, signed.PolicyManager().Sign(signed.state))
	require.NoError(t, storage.SaveState(signed.state))
	require.NoError(t, signed.Close())

	verified := newPolicyAuth(t, storage, provider, DefaultConfig().PINMinLength)
	require.False(t, verified.TamperDetected.Load())
	require.NoError(t, verified.requirePolicyIntegrity())
}

// TestRequirePolicyIntegrityRefusesWhenTampered is the gate's error path.
func TestRequirePolicyIntegrityRefusesWhenTampered(t *testing.T) {
	tampered, _, _ := newTamperedAuth(t)
	require.ErrorIs(t, tampered.requirePolicyIntegrity(), ErrPolicyTamperLocked)
}

// TestTamperLockRefusesUserModeCTAPCommands proves a device booting with a
// tampered policy no longer serves makeCredential — a complete, valid request
// is refused with CTAP2_ERR_INTEGRITY_FAILURE before it is even decoded — and
// that every other user-mode command is refused the same way.
func TestTamperLockRefusesUserModeCTAPCommands(t *testing.T) {
	tampered, _, _ := newTamperedAuth(t)

	resp, err := tampered.ProcessCBOR(CmdMakeCredential, completeMakeCredentialCBOR(t))
	require.ErrorIs(t, err, ErrPolicyTamperLocked)
	require.Equal(t, []byte{StatusIntegrityFailure}, resp)

	userMode := []byte{
		CmdMakeCredential, CmdGetAssertion, CmdGetNextAssertion, CmdClientPIN,
		CmdReset, CmdBioEnrollment, CmdCredentialManagement, CmdLargeBlobs, CmdConfig,
	}
	for _, cmd := range userMode {
		resp, err := tampered.ProcessCBOR(cmd, nil)
		require.ErrorIs(t, err, ErrPolicyTamperLocked, "command 0x%02x", cmd)
		require.Equal(t, []byte{StatusIntegrityFailure}, resp, "command 0x%02x", cmd)
	}
}

// TestTamperLockLeavesDiscoveryOpen proves the lock is not a brick from the
// platform's side: getInfo and selection still answer, so the device is
// visible and its state can be read.
func TestTamperLockLeavesDiscoveryOpen(t *testing.T) {
	tampered, _, _ := newTamperedAuth(t)

	for _, cmd := range []byte{CmdGetInfo, CmdSelection} {
		resp, err := tampered.ProcessCBOR(cmd, nil)
		require.NoError(t, err, "command 0x%02x", cmd)
		require.Equal(t, byte(StatusOK), resp[0], "command 0x%02x", cmd)
	}
}

// TestTamperLockRefusesGoAPI proves in-process callers are locked too: the Go
// API MakeCredential and GetAssertion paths do not pass through the CBOR
// dispatch, so they carry the gate themselves.
func TestTamperLockRefusesGoAPI(t *testing.T) {
	tampered, _, _ := newTamperedAuth(t)

	_, err := tampered.MakeCredential(protectCDH(),
		RelyingParty{ID: "example.com", Name: "Example"}, protectUser(), protectParams(), nil)
	require.ErrorIs(t, err, ErrPolicyTamperLocked)

	_, err = tampered.GetAssertion(protectCDH(), "example.com", nil, nil)
	require.ErrorIs(t, err, ErrPolicyTamperLocked)
}

// getInfoOptions runs getInfo through the CBOR dispatch and returns the
// decoded options map, so a test reads exactly what a platform reads.
func getInfoOptions(t *testing.T, auth *Authenticator) map[interface{}]interface{} {
	t.Helper()
	resp, err := auth.ProcessCBOR(CmdGetInfo, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	var info map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &info))
	options, ok := info[getInfoKeyOptions].(map[interface{}]interface{})
	require.True(t, ok, "getInfo must carry an options map")
	return options
}

// TestTamperLockReportedInGetInfo proves the state a locked device keeps
// discoverable is reported truthfully: the vendor option is present and true
// while locked, and absent on a clean device so the default is never
// advertised.
func TestTamperLockReportedInGetInfo(t *testing.T) {
	tampered, _, _ := newTamperedAuth(t)
	require.Equal(t, true, getInfoOptions(t, tampered)[getInfoOptionPolicyTamperLocked])

	_, present := getInfoOptions(t, newProtectAuth(t))[getInfoOptionPolicyTamperLocked]
	require.False(t, present, "a clean device must not advertise the option at all")
}

// TestTamperLockLiftsAfterSOResign proves the recovery path the lock's doc
// comment promises, end to end: the Security Officer re-signs the policy over
// the configuration the device actually has, and the authenticator re-opened
// against that state verifies clean, stops advertising the lock, and serves
// registrations again over CTAP. No reset, no reflash.
func TestTamperLockLiftsAfterSOResign(t *testing.T) {
	tampered, storage, provider := newTamperedAuth(t)
	_, locked := tampered.ProcessCBOR(CmdMakeCredential, completeMakeCredentialCBOR(t))
	require.ErrorIs(t, locked, ErrPolicyTamperLocked, "fixture must be locked before recovery")

	// The SO acknowledges the changed configuration by re-signing it.
	require.NoError(t, tampered.PolicyManager().Sign(tampered.state))
	require.NoError(t, storage.SaveState(tampered.state))
	require.NoError(t, tampered.Close())

	resigned := newPolicyAuth(t, storage, provider, 12)
	require.False(t, resigned.TamperDetected.Load())
	require.NoError(t, resigned.requirePolicyIntegrity())

	_, present := getInfoOptions(t, resigned)[getInfoOptionPolicyTamperLocked]
	require.False(t, present, "a recovered device must stop advertising the lock")

	resp, err := resigned.ProcessCBOR(CmdMakeCredential, completeMakeCredentialCBOR(t))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0], "registration over CTAP must be served again")

	goResp, err := resigned.MakeCredential(protectCDH(),
		RelyingParty{ID: "example.com", Name: "Example"}, protectUser(), protectParams(), nil)
	require.NoError(t, err)
	require.NotNil(t, goResp)
}

// TestTamperLockedMapsToIntegrityFailure pins the CTAP status for the lock.
func TestTamperLockedMapsToIntegrityFailure(t *testing.T) {
	require.Equal(t, byte(StatusIntegrityFailure), errorToStatus(ErrPolicyTamperLocked))
}
