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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

type protectPresence struct {
	mu      sync.Mutex
	approve bool
}

func (h *protectPresence) RequestUserPresence(
	ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return &UserPresenceResult{Approved: h.approve}, nil
}

func (h *protectPresence) RequestUserVerification(
	ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrUserVerificationDenied
}

func newProtectAuth(t *testing.T) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		RPPolicyStore:       NewMemoryRPPolicyStore(),
		UserPresenceHandler: &protectPresence{approve: true},
	})
	require.NoError(t, err)
	return auth
}

func protectCDH() []byte {
	h := make([]byte, ClientDataHashSize)
	for i := range h {
		h[i] = byte(0x30 + i%16)
	}
	return h
}

func protectUser() User {
	return User{ID: []byte("user-id"), Name: "user", DisplayName: "User"}
}

func protectParams() []PublicKeyCredentialParam {
	return []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}
}

// registerAtCredProtectLevel creates a discoverable credential at the given
// credProtect level and asserts the level really was stored, so a later failure
// is about enforcement rather than about the credential never being protected.
func registerAtCredProtectLevel(t *testing.T, auth *Authenticator, rpID string, level uint8) []byte {
	t.Helper()
	resp, err := auth.MakeCredential(protectCDH(),
		RelyingParty{ID: rpID, Name: "Example"}, protectUser(), protectParams(),
		&MakeCredentialOptions{
			Options:    map[string]bool{"rk": true},
			Extensions: map[string]interface{}{"credProtect": level},
		})
	require.NoError(t, err)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)

	stored, err := auth.storage.Load(authData.CredentialID)
	require.NoError(t, err)
	require.Equal(t, level, stored.CredProtect, "precondition: credProtect must be stored")

	return authData.CredentialID
}

// grantGetAssertionToken installs a live pinUvAuthToken carrying the ga
// permission and returns the matching pinUvAuthParam for clientDataHash.
func grantGetAssertionToken(auth *Authenticator, clientDataHash []byte) []byte {
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionGetAssertion)
	return pinUvAuthParamFor(token, clientDataHash)
}

// --------------------------------------------------------------------------
// #215 — CTAP 2.1 §12.1 credProtect enforcement
// --------------------------------------------------------------------------

// TestCredProtectLevel3RefusedWithoutUV proves a level-3 credential is not
// returned without user verification, even when named explicitly in an
// allowList. Before the fix, checkAssertionCredentialProtection returned nil
// and the assertion was produced with the UV bit clear.
func TestCredProtectLevel3RefusedWithoutUV(t *testing.T) {
	auth := newProtectAuth(t)
	credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

	_, err := auth.GetAssertion(protectCDH(), "example.com",
		[]CredentialDescriptor{{Type: "public-key", ID: credID}},
		&GetAssertionOptions{Options: map[string]bool{"up": true}})

	require.ErrorIs(t, err, ErrNoCredentials,
		"a credProtect level 3 credential must not be usable without user verification")
}

// TestCredProtectLevel3AllowedWithUV is the positive half: real user
// verification unlocks the same credential.
func TestCredProtectLevel3AllowedWithUV(t *testing.T) {
	auth := newProtectAuth(t)
	credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

	cdh := protectCDH()
	param := grantGetAssertionToken(auth, cdh)

	resp, err := auth.GetAssertion(cdh, "example.com",
		[]CredentialDescriptor{{Type: "public-key", ID: credID}},
		&GetAssertionOptions{
			Options:           map[string]bool{"up": true},
			PINUVAuthParam:    param,
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err, "user verification must unlock a level 3 credential")

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.True(t, authData.UserVerified(), "the assertion must report the verification that unlocked it")
}

// TestCredProtectLevel2HiddenFromEmptyAllowListWithoutUV proves a level-2
// credential is not disclosed by a discoverable-credential enumeration without
// user verification. Disclosure would leak the credential ID and the user's id,
// name and display name.
func TestCredProtectLevel2HiddenFromEmptyAllowListWithoutUV(t *testing.T) {
	auth := newProtectAuth(t)
	registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptionalWithList)

	_, err := auth.GetAssertion(protectCDH(), "example.com", nil,
		&GetAssertionOptions{Options: map[string]bool{"up": true}})

	require.ErrorIs(t, err, ErrNoCredentials,
		"a credProtect level 2 credential must not be disclosed by an empty-allowList enumeration without UV")
}

// TestCredProtectLevel2AllowedWhenNamedInAllowList proves level 2 means what it
// says: naming the credential ID is sufficient, no user verification required.
func TestCredProtectLevel2AllowedWhenNamedInAllowList(t *testing.T) {
	auth := newProtectAuth(t)
	credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptionalWithList)

	_, err := auth.GetAssertion(protectCDH(), "example.com",
		[]CredentialDescriptor{{Type: "public-key", ID: credID}},
		&GetAssertionOptions{Options: map[string]bool{"up": true}})

	require.NoError(t, err,
		"a credProtect level 2 credential named in an allowList must be usable without UV")
}

// TestCredProtectLevel1Unrestricted keeps the default path honest: level 1 and
// unset credentials are not affected by the new filtering.
func TestCredProtectLevel1Unrestricted(t *testing.T) {
	auth := newProtectAuth(t)
	registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptional)

	_, err := auth.GetAssertion(protectCDH(), "example.com", nil,
		&GetAssertionOptions{Options: map[string]bool{"up": true}})

	require.NoError(t, err, "a credProtect level 1 credential carries no restriction")
}

// TestCredentialProtectionSatisfiedMatrix pins the §12.1 table directly, so a
// future edit to one branch cannot quietly change another.
func TestCredentialProtectionSatisfiedMatrix(t *testing.T) {
	cases := []struct {
		name      string
		level     uint8
		allowList bool
		uv        bool
		want      bool
	}{
		{"unset, no allowList, no UV", CredProtectNone, false, false, true},
		{"level 1, no allowList, no UV", CredProtectUserVerificationOptional, false, false, true},
		{"level 2, allowList, no UV", CredProtectUserVerificationOptionalWithList, true, false, true},
		{"level 2, no allowList, no UV", CredProtectUserVerificationOptionalWithList, false, false, false},
		{"level 2, no allowList, UV", CredProtectUserVerificationOptionalWithList, false, true, true},
		{"level 3, allowList, no UV", CredProtectUserVerificationRequired, true, false, false},
		{"level 3, no allowList, no UV", CredProtectUserVerificationRequired, false, false, false},
		{"level 3, allowList, UV", CredProtectUserVerificationRequired, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := &StoredCredential{CredProtect: tc.level}
			require.Equal(t, tc.want,
				credentialProtectionSatisfied(cred, tc.allowList, tc.uv))
		})
	}
}

// TestCanAuthorizePinUvAuthTokenDoesNotConsumeToken proves the read-only check
// used at credential-selection time spends nothing: it must not bind the
// permissions RP ID, nor refresh the inactivity timer, nor discard an expired
// token. Otherwise asking the question would consume the single use that the
// authoritative call later commits.
func TestCanAuthorizePinUvAuthTokenDoesNotConsumeToken(t *testing.T) {
	auth := newProtectAuth(t)
	cdh := protectCDH()
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionGetAssertion)
	before := auth.pinState.protocol.tokenLastUsed

	require.NoError(t, auth.CanAuthorizePinUvAuthToken(cdh,
		pinUvAuthParamFor(token, cdh), PINPermissionGetAssertion, "example.com"))

	auth.mu.RLock()
	rpID := auth.pinState.protocol.tokenRPID
	lastUsed := auth.pinState.protocol.tokenLastUsed
	auth.mu.RUnlock()

	require.Empty(t, rpID, "the read-only check must not bind the permissions RP ID")
	require.Equal(t, before, lastUsed, "the read-only check must not refresh the inactivity timer")
}

// TestLookupCredentialsForAssertionIgnoresCredProtect pins the deliberate
// difference between the two lookups: the transport's deferral heuristic asks
// only whether the authenticator holds anything for the RP, and must keep
// answering the same way for indexed and non-indexed storage backends.
func TestLookupCredentialsForAssertionIgnoresCredProtect(t *testing.T) {
	auth := newProtectAuth(t)
	registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

	req := &GetAssertionRequest{RPID: "example.com", ClientDataHash: protectCDH()}

	unfiltered, err := auth.lookupCredentialsForAssertion(req)
	require.NoError(t, err)
	require.Len(t, unfiltered, 1, "the deferral lookup must not apply credProtect filtering")

	filtered, err := auth.findMatchingCredentialsForAssertion(req, false)
	require.NoError(t, err)
	require.Empty(t, filtered, "the assertion lookup must apply credProtect filtering")
}

// --------------------------------------------------------------------------
// #216 D — attestation conveyance is not a statement format
// --------------------------------------------------------------------------

// TestAttestationOverrideRefusesWhenUnhonourable proves an SO policy demanding
// attestation produces an error rather than a credential telling the relying
// party that no attestation was available. Before the fix, "direct" was written
// into the statement-format slot, missed every case of the format switch, and
// returned "none".
func TestAttestationOverrideRefusesWhenUnhonourable(t *testing.T) {
	auth := newProtectAuth(t)
	req := &MakeCredentialRequest{
		ClientDataHash:   protectCDH(),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             protectUser(),
		PubKeyCredParams: protectParams(),
	}

	for _, preference := range []string{
		AttestationConveyanceDirect,
		AttestationConveyanceIndirect,
		AttestationConveyanceEnterprise,
	} {
		t.Run(preference, func(t *testing.T) {
			policy := &RPPolicy{RPID: "example.com", AttestationOverride: preference}
			fmtName, _, err := auth.buildMakeCredentialAttestation(
				make([]byte, 37), req.ClientDataHash, req, policy)

			require.Error(t, err,
				"an attestation conveyance that cannot be honoured must be refused")
			require.NotEqual(t, AttestationFormatNone, fmtName,
				"refusal must not be reported as a successful fmt=none")
		})
	}
}

// TestAttestationOverrideNoneIsHonoured proves the one preference that can
// always be satisfied still works, and still reports "none" truthfully.
func TestAttestationOverrideNoneIsHonoured(t *testing.T) {
	auth := newProtectAuth(t)
	req := &MakeCredentialRequest{
		ClientDataHash:   protectCDH(),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             protectUser(),
		PubKeyCredParams: protectParams(),
	}
	policy := &RPPolicy{RPID: "example.com", AttestationOverride: AttestationConveyanceNone}

	fmtName, attStmt, err := auth.buildMakeCredentialAttestation(
		make([]byte, 37), req.ClientDataHash, req, policy)

	require.NoError(t, err)
	require.Equal(t, AttestationFormatNone, fmtName)
	require.Empty(t, attStmt)
}

// TestResolveAttestationOverrideRejectsUnknownPreference proves an
// unrecognised value is refused rather than silently treated as "none".
func TestResolveAttestationOverrideRejectsUnknownPreference(t *testing.T) {
	auth := newProtectAuth(t)

	_, err := auth.resolveAttestationOverride("packed")
	require.ErrorIs(t, err, ErrAttestationOverrideUnsupported,
		"a statement format is not a conveyance preference and must be rejected")

	_, err = auth.resolveAttestationOverride("nonsense")
	require.ErrorIs(t, err, ErrAttestationOverrideUnsupported)
}

// TestBuildMakeCredentialAttestationIsRaceFree exercises the bug that made the
// old swap-and-restore dangerous: two concurrent registrations under different
// RP policies shared one Config.AttestationFormat field, so one request could
// observe — and attest under — the other's format.
//
// Run under -race this fails on the old code and passes on the new, where the
// format is a parameter and no shared state is mutated.
func TestBuildMakeCredentialAttestationIsRaceFree(t *testing.T) {
	auth := newProtectAuth(t)
	authData := make([]byte, 37)
	formatBefore := auth.config.AttestationFormat

	reqFor := func(rpID string) *MakeCredentialRequest {
		return &MakeCredentialRequest{
			ClientDataHash:   protectCDH(),
			RP:               RelyingParty{ID: rpID, Name: rpID},
			User:             protectUser(),
			PubKeyCredParams: protectParams(),
		}
	}

	// Two RPs whose policies resolve differently: one asks for no attestation,
	// the other for attestation this authenticator cannot produce.
	policies := []*RPPolicy{
		{RPID: "none.example", AttestationOverride: AttestationConveyanceNone},
		{RPID: "direct.example", AttestationOverride: AttestationConveyanceDirect},
	}

	const iterations = 64
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		for _, policy := range policies {
			wg.Add(1)
			go func(p *RPPolicy) {
				defer wg.Done()
				fmtName, _, err := auth.buildMakeCredentialAttestation(
					authData, protectCDH(), reqFor(p.RPID), p)

				// Each goroutine must get the answer its own policy dictates,
				// never the other's.
				if p.AttestationOverride == AttestationConveyanceNone {
					require.NoError(t, err)
					require.Equal(t, AttestationFormatNone, fmtName)
					return
				}
				require.ErrorIs(t, err, ErrAttestationOverrideUnsupported)
			}(policy)
		}
	}
	wg.Wait()

	require.Equal(t, formatBefore, auth.config.AttestationFormat,
		"building an attestation statement must not leave shared config modified")
}

// TestGoAPIMakeCredentialHonoursRPBlock proves the Go API applies an SO's RP
// block. It previously consulted no RP policy at all, so an SO who blocked an
// RP blocked it only for CBOR callers.
func TestGoAPIMakeCredentialHonoursRPBlock(t *testing.T) {
	auth := newProtectAuth(t)
	require.NoError(t, auth.rpPolicyStore.SetPolicy(&RPPolicy{
		RPID:    "blocked.example",
		Blocked: true,
	}))

	_, err := auth.MakeCredential(protectCDH(),
		RelyingParty{ID: "blocked.example", Name: "Blocked"}, protectUser(), protectParams(),
		&MakeCredentialOptions{Options: map[string]bool{"rk": true}})

	require.ErrorIs(t, err, ErrRPBlocked,
		"an SO's RP block must fire for in-process callers too")
}

// TestGoAPIMakeCredentialHonoursAttestationOverride proves the Go API refuses a
// registration whose RP policy demands attestation this authenticator cannot
// produce, rather than silently issuing a credential with fmt=none.
func TestGoAPIMakeCredentialHonoursAttestationOverride(t *testing.T) {
	auth := newProtectAuth(t)
	require.NoError(t, auth.rpPolicyStore.SetPolicy(&RPPolicy{
		RPID:                "attested.example",
		AttestationOverride: AttestationConveyanceDirect,
	}))

	_, err := auth.MakeCredential(protectCDH(),
		RelyingParty{ID: "attested.example", Name: "Attested"}, protectUser(), protectParams(),
		&MakeCredentialOptions{Options: map[string]bool{"rk": true}})

	require.ErrorIs(t, err, ErrAttestationOverrideUnsupported,
		"an SO attestation override must fire for in-process callers too")
}

// TestGoAPIMakeCredentialUnaffectedWithoutPolicy keeps the ordinary path
// honest: with no policy for the RP, nothing changes.
func TestGoAPIMakeCredentialUnaffectedWithoutPolicy(t *testing.T) {
	auth := newProtectAuth(t)

	_, err := auth.MakeCredential(protectCDH(),
		RelyingParty{ID: "plain.example", Name: "Plain"}, protectUser(), protectParams(),
		&MakeCredentialOptions{Options: map[string]bool{"rk": true}})

	require.NoError(t, err)
}

// --------------------------------------------------------------------------
// #216 E2 — the policy HMAC must cover every security-relevant setting
// --------------------------------------------------------------------------

// TestPolicyHMACCoversSecuritySettings proves that flipping any setting the
// HMAC exists to protect changes the signed bytes. Before the fix an attacker
// with exactly the filesystem write access this HMAC detects could flip
// RequireUserPresence to false and still verify.
func TestPolicyHMACCoversSecuritySettings(t *testing.T) {
	baseline, err := ExtractPolicyFields(DefaultConfig()).Canonical()
	require.NoError(t, err)

	mutations := map[string]func(*Config){
		"RequireUserPresence":   func(c *Config) { c.RequireUserPresence = !c.RequireUserPresence },
		"EnableUserIntentCheck": func(c *Config) { c.EnableUserIntentCheck = !c.EnableUserIntentCheck },
		"AttestationFormat":     func(c *Config) { c.AttestationFormat = AttestationFormatPacked },
		"EnablePIN":             func(c *Config) { c.EnablePIN = !c.EnablePIN },
		"EnableResidentKey":     func(c *Config) { c.EnableResidentKey = !c.EnableResidentKey },
		"EnableHMACSecret":      func(c *Config) { c.EnableHMACSecret = !c.EnableHMACSecret },
		"SupportedAlgorithms":   func(c *Config) { c.SupportedAlgorithms = append(c.SupportedAlgorithms, COSEAlgRS256) },
		"AAGUID":                func(c *Config) { c.AAGUID = [16]byte{0xFF} },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			mutate(cfg)
			canon, err := ExtractPolicyFields(cfg).Canonical()
			require.NoError(t, err)
			require.NotEqual(t, string(baseline), string(canon),
				"changing %s must change the signed policy bytes", name)
		})
	}
}

// TestPolicySchemaChangeIsNotReportedAsTampering proves the distinction that
// makes extending the field set safe: a policy signed under a different schema
// reports ErrPolicySchemaChanged, not ErrPolicyTampered. Conflating them would
// make a routine upgrade look like an attack on every signed device at once.
func TestPolicySchemaChangeIsNotReportedAsTampering(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	cfg := DefaultConfig()
	pm := NewPolicyManager(cfg, provider)

	state := NewAuthenticatorState()
	require.NoError(t, pm.Sign(state))

	// The stored policy was signed under an older field set.
	state.SignedPolicyFields.SchemaVersion = PolicyFieldsSchemaVersion - 1

	diag, err := pm.Verify(state)
	require.ErrorIs(t, err, ErrPolicySchemaChanged)
	require.NotErrorIs(t, err, ErrPolicyTampered,
		"a schema change must never be reported as tampering")
	require.NotNil(t, diag)
	require.True(t, diag.SchemaChanged)
	require.Equal(t, PolicyFieldsSchemaVersion-1, diag.SignedSchemaVersion)
	require.Equal(t, PolicyFieldsSchemaVersion, diag.CurrentSchemaVersion)
	require.Empty(t, diag.Mismatches,
		"a snapshot from another schema deserializes with zero values for fields it never carried, so naming mismatches would accuse settings nobody touched")
}

// TestPolicySchemaChangeDoesNotSetTamperDetected proves the distinction reaches
// the authenticator: a schema change must not raise the tamper flag, and must
// not prevent the authenticator from starting.
func TestPolicySchemaChangeDoesNotSetTamperDetected(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	storage := NewMemoryStorage()
	signCfg := DefaultConfig()
	state := NewAuthenticatorState()
	require.NoError(t, NewPolicyManager(signCfg, provider).Sign(state))
	state.SignedPolicyFields.SchemaVersion = PolicyFieldsSchemaVersion - 1
	require.NoError(t, storage.SaveState(state))

	cfg := DefaultConfig()
	cfg.Storage = storage
	cfg.PolicyIntegrityProvider = provider

	auth, err := NewAuthenticator(cfg)
	require.NoError(t, err, "a schema change must not prevent startup")
	defer func() { _ = auth.Close() }()

	require.False(t, auth.TamperDetected.Load(),
		"a policy signed under an older schema is not evidence of tampering")
}

// TestPolicySignStampsCurrentSchemaVersion proves a freshly signed policy
// records the version it was signed under, so the next field-set change is
// detectable rather than silent.
func TestPolicySignStampsCurrentSchemaVersion(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	provider, err := NewSoftwarePolicyProvider(key)
	require.NoError(t, err)

	state := NewAuthenticatorState()
	require.NoError(t, NewPolicyManager(DefaultConfig(), provider).Sign(state))

	require.Equal(t, PolicyFieldsSchemaVersion, state.SignedPolicyFields.SchemaVersion)

	diag, err := NewPolicyManager(DefaultConfig(), provider).Verify(state)
	require.NoError(t, err, "a policy signed by this build must verify against it")
	require.True(t, diag.Valid)
}

// TestPolicyMismatchNamesChangedField proves the tamper report identifies the
// field that moved, not merely that something did.
func TestPolicyMismatchNamesChangedField(t *testing.T) {
	signed := ExtractPolicyFields(DefaultConfig())

	tampered := DefaultConfig()
	tampered.RequireUserPresence = !tampered.RequireUserPresence
	current := ExtractPolicyFields(tampered)

	mismatches := computeMismatches(current, signed)
	require.Len(t, mismatches, 1)
	require.Equal(t, "requireUserPresence", mismatches[0].Field)
}
