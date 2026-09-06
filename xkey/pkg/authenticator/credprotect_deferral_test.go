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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// --------------------------------------------------------------------------
// #261 — the no-credentials deferral answer respects credProtect
//
// HasMatchingCredentials drives the HID adapter's multi-authenticator
// deferral. Before the fix it reported a credential's existence to any caller
// on the transport regardless of its protection level: the oracle #217 closed
// for excludeList and #215 for assertions, surviving on a third path.
//
// Every scenario runs against both storage shapes the function distinguishes:
// MemoryStorage, which takes the storage-scan path, and BackendStorage, whose
// in-memory index answers the discoverable case with zero storage I/O.
// --------------------------------------------------------------------------

// deferralStorages returns one constructor per storage shape so a scenario
// runs once on the scan path and once on the indexed path.
func deferralStorages(t *testing.T) map[string]func(t *testing.T) CredentialStorage {
	t.Helper()
	return map[string]func(t *testing.T) CredentialStorage{
		"scan": func(t *testing.T) CredentialStorage {
			return NewMemoryStorage()
		},
		"indexed": func(t *testing.T) CredentialStorage {
			backend := xkms.NewStorageMemory()
			t.Cleanup(func() { _ = backend.Close() })
			bs, err := NewBackendStorage(backend, "deferral/")
			require.NoError(t, err)
			bs.WaitForIndex()
			return bs
		},
	}
}

// newDeferralAuth mirrors newProtectAuth over an arbitrary credential storage.
func newDeferralAuth(t *testing.T, storage CredentialStorage) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		Storage:             storage,
		EnablePIN:           true,
		EnableResidentKey:   true,
		RPPolicyStore:       NewMemoryRPPolicyStore(),
		UserPresenceHandler: &protectPresence{approve: true},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// deferralProbe encodes the GetAssertion payload the HID adapter hands to
// HasMatchingCredentials. A nil pinUvAuthParam encodes a request without user
// verification; a non-nil one is sent with PIN protocol 1.
func deferralProbe(t *testing.T, rpID string, clientDataHash, pinUvAuthParam []byte, allowListIDs ...[]byte) []byte {
	t.Helper()
	params := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
	}
	if len(allowListIDs) > 0 {
		list := make([]interface{}, 0, len(allowListIDs))
		for _, id := range allowListIDs {
			list = append(list, map[string]interface{}{"type": "public-key", "id": id})
		}
		params[getAssertionParamAllowList] = list
	}
	if pinUvAuthParam != nil {
		params[getAssertionParamPINUVAuthParam] = pinUvAuthParam
		params[getAssertionParamPINUVAuthProtocol] = PINProtocol1
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// TestDeferralHidesLevel3WithoutUV is the defect test: a credProtect level-3
// credential must not be reported to the deferral heuristic when the request
// carries no user verification, whether the platform enumerates the RP or names
// the credential in an allowList. Before the fix both probes reported true.
func TestDeferralHidesLevel3WithoutUV(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

			hasMatch, parseable, hasPINAuth, rpID := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil))
			require.True(t, parseable)
			require.False(t, hasPINAuth)
			require.Equal(t, "example.com", rpID)
			require.False(t, hasMatch,
				"a level-3 credential must be invisible to the deferral heuristic without user verification")

			hasMatch, parseable, _, _ = auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil, credID))
			require.True(t, parseable)
			require.False(t, hasMatch,
				"naming a level-3 credential in an allowList must not disclose it without user verification")
		})
	}
}

// TestDeferralShowsLevel3WithUV is the positive half: a live pinUvAuthToken
// with the ga permission makes the same credential visible, so a verified
// platform is not wrongly deferred to another authenticator.
func TestDeferralShowsLevel3WithUV(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

			cdh := protectCDH()
			param := grantGetAssertionToken(auth, cdh)

			hasMatch, parseable, hasPINAuth, _ := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", cdh, param))
			require.True(t, parseable)
			require.True(t, hasPINAuth)
			require.True(t, hasMatch, "user verification must make a level-3 credential visible")

			hasMatch, _, _, _ = auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", cdh, param, credID))
			require.True(t, hasMatch, "user verification must make an allowListed level-3 credential visible")

			// Asking must not spend the token: the real getAssertion that
			// follows the deferral decision still has to authorize.
			require.NoError(t, auth.CanAuthorizePinUvAuthToken(cdh, param, PINPermissionGetAssertion, "example.com"))
		})
	}
}

// TestDeferralInvalidPINAuthHidesLevel3 proves the visibility decision rests
// on a verified token, not on the mere presence of pinUvAuthParam: a forged
// parameter neither discloses the credential nor changes the hasPINAuth
// signal the adapter uses to skip deferral.
func TestDeferralInvalidPINAuthHidesLevel3(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)

			forged := make([]byte, PINAuthSizeV1)
			hasMatch, parseable, hasPINAuth, _ := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), forged))
			require.True(t, parseable)
			require.True(t, hasPINAuth, "the adapter still learns a pinUvAuthParam was sent")
			require.False(t, hasMatch, "a forged pinUvAuthParam must not unlock a level-3 credential")
		})
	}
}

// TestDeferralShowsLevel1WithoutUV guards the other direction: an unprotected
// credential keeps answering, so deferral still works for ordinary
// registrations.
func TestDeferralShowsLevel1WithoutUV(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptional)

			hasMatch, parseable, _, _ := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil))
			require.True(t, parseable)
			require.True(t, hasMatch, "a level-1 credential is visible without user verification")

			hasMatch, _, _, _ = auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil, credID))
			require.True(t, hasMatch, "an allowListed level-1 credential is visible without user verification")
		})
	}
}

// TestDeferralLevel2FollowsAllowList applies the §12.1 level-2 rule: hidden
// from an RP enumeration without user verification, visible once the platform
// names the credential in an allowList.
func TestDeferralLevel2FollowsAllowList(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			credID := registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptionalWithList)

			hasMatch, parseable, _, _ := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil))
			require.True(t, parseable)
			require.False(t, hasMatch, "a level-2 credential must not answer an RP enumeration without user verification")

			hasMatch, _, _, _ = auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil, credID))
			require.True(t, hasMatch, "a level-2 credential named in an allowList is visible")
		})
	}
}

// TestDeferralMixedLevelsAnswersForVisibleOnly proves the index answers per
// credential rather than per RP: a protected credential beside an unprotected
// one neither hides the unprotected one nor is disclosed by it.
func TestDeferralMixedLevelsAnswersForVisibleOnly(t *testing.T) {
	for name, newStorage := range deferralStorages(t) {
		t.Run(name, func(t *testing.T) {
			auth := newDeferralAuth(t, newStorage(t))
			registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationRequired)
			registerAtCredProtectLevel(t, auth, "example.com", CredProtectUserVerificationOptional)
			registerAtCredProtectLevel(t, auth, "protected.example", CredProtectUserVerificationRequired)

			hasMatch, _, _, _ := auth.HasMatchingCredentials(
				deferralProbe(t, "example.com", protectCDH(), nil))
			require.True(t, hasMatch, "the level-1 credential still answers for its RP")

			hasMatch, _, _, _ = auth.HasMatchingCredentials(
				deferralProbe(t, "protected.example", protectCDH(), nil))
			require.False(t, hasMatch, "an RP holding only level-3 credentials answers as empty")
		})
	}
}

// --------------------------------------------------------------------------
// BackendStorage index: the protection level is indexed at write time
// --------------------------------------------------------------------------

// storeDeferralCredential persists a discoverable credential for rpID at the
// given credProtect level directly through the storage, bypassing
// makeCredential so the index writers are exercised in isolation.
func storeDeferralCredential(t *testing.T, s *BackendStorage, rpID string, id byte, level uint8) *StoredCredential {
	t.Helper()
	cred := &StoredCredential{
		CredentialID: []byte{id, id, id, id},
		RPID:         rpID,
		UserID:       []byte("user"),
		Discoverable: true,
		CredProtect:  level,
	}
	require.NoError(t, s.Store(cred))
	return cred
}

// TestIndexStoreRecordsProtectionLevel proves Store indexes the level and
// HasDiscoverableForRP applies the §12.1 rule from it: level 1 and unset are
// visible without user verification; level 2 and 3 only with it.
func TestIndexStoreRecordsProtectionLevel(t *testing.T) {
	cases := []struct {
		name          string
		level         uint8
		visibleNoUV   bool
		visibleWithUV bool
	}{
		{"unset", CredProtectNone, true, true},
		{"level 1", CredProtectUserVerificationOptional, true, true},
		{"level 2", CredProtectUserVerificationOptionalWithList, false, true},
		{"level 3", CredProtectUserVerificationRequired, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := xkms.NewStorageMemory()
			defer func() { _ = backend.Close() }()
			s, err := NewBackendStorage(backend, "deferral/")
			require.NoError(t, err)
			s.WaitForIndex()

			storeDeferralCredential(t, s, "example.com", 0x01, tc.level)

			require.Equal(t, tc.visibleNoUV, s.HasDiscoverableForRP("example.com", false))
			require.Equal(t, tc.visibleWithUV, s.HasDiscoverableForRP("example.com", true))
			require.True(t, s.HasCredentialsForRP("example.com"),
				"the storage-level existence check counts protected credentials")
		})
	}
}

// TestIndexRebuildCarriesProtectionLevel proves an index rebuilt from
// persisted credentials on a fresh BackendStorage carries each credential's
// level, so a restart does not reopen the oracle.
func TestIndexRebuildCarriesProtectionLevel(t *testing.T) {
	backend := xkms.NewStorageMemory()
	defer func() { _ = backend.Close() }()

	first, err := NewBackendStorage(backend, "deferral/")
	require.NoError(t, err)
	first.WaitForIndex()
	storeDeferralCredential(t, first, "protected.example", 0x01, CredProtectUserVerificationRequired)
	storeDeferralCredential(t, first, "listed.example", 0x02, CredProtectUserVerificationOptionalWithList)
	storeDeferralCredential(t, first, "open.example", 0x03, CredProtectUserVerificationOptional)
	storeDeferralCredential(t, first, "legacy.example", 0x04, CredProtectNone)
	require.NoError(t, first.Close())

	rebuilt, err := NewBackendStorage(backend, "deferral/")
	require.NoError(t, err)
	rebuilt.WaitForIndex()
	defer func() { _ = rebuilt.Close() }()

	require.False(t, rebuilt.HasDiscoverableForRP("protected.example", false),
		"a rebuilt index must still hide a level-3 credential without user verification")
	require.True(t, rebuilt.HasDiscoverableForRP("protected.example", true))
	require.False(t, rebuilt.HasDiscoverableForRP("listed.example", false),
		"a rebuilt index must still hide a level-2 credential from an enumeration without user verification")
	require.True(t, rebuilt.HasDiscoverableForRP("listed.example", true))
	require.True(t, rebuilt.HasDiscoverableForRP("open.example", false))
	require.True(t, rebuilt.HasDiscoverableForRP("legacy.example", false),
		"a credential stored without the extension is level 1, not unknown")

	rebuilt.mu.RLock()
	defer rebuilt.mu.RUnlock()
	for rpID, want := range map[string]uint8{
		"protected.example": CredProtectUserVerificationRequired,
		"listed.example":    CredProtectUserVerificationOptionalWithList,
		"open.example":      CredProtectUserVerificationOptional,
		"legacy.example":    CredProtectUserVerificationOptional,
	} {
		require.Len(t, rebuilt.rpIndex[rpID], 1)
		require.Equal(t, want, rebuilt.rpIndex[rpID][0].protection.level(), rpID)
	}
}

// TestIndexUpdateFollowsProtectionLevel proves the update branch of
// indexUpsert rewrites the level, so re-storing a credential (as every
// signCount increment does) never leaves a stale level in the index.
func TestIndexUpdateFollowsProtectionLevel(t *testing.T) {
	backend := xkms.NewStorageMemory()
	defer func() { _ = backend.Close() }()
	s, err := NewBackendStorage(backend, "deferral/")
	require.NoError(t, err)
	s.WaitForIndex()

	cred := storeDeferralCredential(t, s, "example.com", 0x01, CredProtectUserVerificationOptional)
	require.True(t, s.HasDiscoverableForRP("example.com", false))

	cred.CredProtect = CredProtectUserVerificationRequired
	require.NoError(t, s.Store(cred))
	require.False(t, s.HasDiscoverableForRP("example.com", false),
		"re-storing at level 3 must update the indexed level")
	require.True(t, s.HasDiscoverableForRP("example.com", true))

	cred.CredProtect = CredProtectUserVerificationOptional
	require.NoError(t, s.Store(cred))
	require.True(t, s.HasDiscoverableForRP("example.com", false),
		"re-storing at level 1 must update the indexed level")

	s.mu.RLock()
	defer s.mu.RUnlock()
	require.Len(t, s.rpIndex["example.com"], 1, "an update must not duplicate the entry")
}

// TestIndexEntryWithoutLevelFailsClosed proves an index entry whose level was
// never recorded is treated as level 3: invisible without user verification,
// visible with it. This is the fail-closed default every writer relies on.
func TestIndexEntryWithoutLevelFailsClosed(t *testing.T) {
	backend := xkms.NewStorageMemory()
	defer func() { _ = backend.Close() }()
	s, err := NewBackendStorage(backend, "deferral/")
	require.NoError(t, err)
	s.WaitForIndex()

	s.mu.Lock()
	s.rpIndex["example.com"] = append(s.rpIndex["example.com"], credentialMeta{
		credentialID: []byte{0x01, 0x02, 0x03, 0x04},
		discoverable: true,
	})
	s.mu.Unlock()

	require.False(t, s.HasDiscoverableForRP("example.com", false),
		"an entry without a recorded level must be treated as protected")
	require.True(t, s.HasDiscoverableForRP("example.com", true),
		"an entry without a recorded level is still usable with user verification")
	require.True(t, s.HasCredentialsForRP("example.com"))
}

// TestIndexedCredProtectLevel pins the two conversions between the stored
// level and the indexed one: the zero stored value denotes level 1, and the
// zero indexed value denotes "never recorded" and reads as level 3.
func TestIndexedCredProtectLevel(t *testing.T) {
	require.Equal(t, CredProtectUserVerificationOptional,
		indexedProtectionOf(&StoredCredential{CredProtect: CredProtectNone}).level(),
		"a stored credential without the extension is level 1")
	for _, level := range []uint8{
		CredProtectUserVerificationOptional,
		CredProtectUserVerificationOptionalWithList,
		CredProtectUserVerificationRequired,
	} {
		require.Equal(t, level, indexedProtectionOf(&StoredCredential{CredProtect: level}).level())
		require.NotZero(t, indexedProtectionOf(&StoredCredential{CredProtect: level}),
			"a recorded level never collides with the never-recorded zero value")
	}
	require.Equal(t, CredProtectUserVerificationRequired, indexedCredProtect(0).level(),
		"a never-recorded level reads as userVerificationRequired")
}

// TestIndexNotReadyHidesEverything guards the fast-path precondition: before
// the index is ready the indexer answers false for every level, and the
// authenticator falls back to the storage scan.
func TestIndexNotReadyHidesEverything(t *testing.T) {
	backend := xkms.NewStorageMemory()
	defer func() { _ = backend.Close() }()
	s := &BackendStorage{
		backend:   backend,
		prefix:    "deferral/",
		rpIndex:   make(map[string][]credentialMeta),
		indexDone: make(chan struct{}),
	}
	storeDeferralCredential(t, s, "example.com", 0x01, CredProtectUserVerificationOptional)

	require.False(t, s.IndexReady())
	require.False(t, s.HasDiscoverableForRP("example.com", false))
	require.False(t, s.HasDiscoverableForRP("example.com", true))
}
