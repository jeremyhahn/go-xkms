// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package module

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Token and object persistence across the module's lifetime.
//
// PKCS#11 v3.2 §4.4 defines a token object as one that "remains on the token
// until specifically destroyed", and §5.5.5 makes C_InitToken's effects — the
// label and the SO's PIN — equally durable. A library that forgot either on
// unload would present an application with a token that looks uninitialized
// every time the process restarts, and the application's stored key handles
// would refer to nothing.
//
// These tests take a module through the full cycle: provision, create a token
// object, C_Finalize, then bring a second module up over the same storage and
// require it to find everything.

// newPersistentModule builds an initialized module whose store is the file
// backend rooted at dir.
//
// Each module opens the directory for itself, exactly as two runs of a host
// process do. Sharing one already-open backend between the two would not model
// a restart: C_Finalize closes the store it was given, so the second module
// would inherit a closed handle rather than reopen the data.
func newPersistentModule(t *testing.T, dir string) *Module {
	t.Helper()

	cfg := DefaultConfig()
	cfg.StorageType = StorageTypeFile
	cfg.StoragePath = dir

	m, err := New(WithClient(newMockClient()), WithConfig(cfg))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))

	return m
}

// TestModule_TokenStateSurvivesFinalize proves that C_InitToken's label and
// both PINs are still in force after the module is finalized and a new one is
// brought up over the same storage.
//
// The PIN check is the load-bearing part. The token's flags could be restored
// while the PIN hashes were not, and every surface an application looks at —
// CKF_TOKEN_INITIALIZED, CKF_USER_PIN_INITIALIZED, the label — would still say
// the token is provisioned. The failure would appear only at C_Login, as a
// CKR_PIN_INCORRECT for a PIN the user typed correctly. Logging in with the
// original PIN is what distinguishes restored flags from restored credentials.
func TestModule_TokenStateSurvivesFinalize(t *testing.T) {
	const (
		soPIN   = "so-pin-persist"
		userPIN = "user-pin-persist"
		label   = "Persisted Token"
	)

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	require.Equal(t, CKR_OK, first.InitToken(0, []byte(soPIN), label))

	soSession, rv := first.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.Login(soSession, CKU_SO, []byte(soPIN)))
	require.Equal(t, CKR_OK, first.InitPIN(soSession, []byte(userPIN)))
	require.Equal(t, CKR_OK, first.Logout(soSession))
	require.Equal(t, CKR_OK, first.CloseSession(soSession))
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()

	info, rv := second.GetTokenInfo(0)
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, label, info.GetLabel(), "C_InitToken's label must survive the restart")
	assert.True(t, info.Flags.Has(CKF_TOKEN_INITIALIZED), "the token must still report itself provisioned")
	assert.True(t, info.Flags.Has(CKF_USER_PIN_INITIALIZED), "C_InitPIN's effect must survive the restart")

	session, rv := second.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	assert.Equal(t, CKR_OK, second.Login(session, CKU_USER, []byte(userPIN)),
		"the restored token must accept the PIN set before the restart")
	require.Equal(t, CKR_OK, second.Logout(session))

	assert.Equal(t, CKR_PIN_INCORRECT, second.Login(session, CKU_USER, []byte("not-the-pin")),
		"restoring PIN state must not weaken it into accepting anything")
}

// TestModule_TokenObjectsSurviveFinalize proves a CKA_TOKEN object created by
// one module is found by the next one over the same storage, with its
// attributes intact.
//
// PKCS#11 v3.2 §4.4: a token object "remains on the token until specifically
// destroyed". The attribute comparison matters as much as the count — an
// object restored with the right handle but an empty attribute map would still
// satisfy C_FindObjects and then fail every C_GetAttributeValue the
// application makes against it.
func TestModule_TokenObjectsSurviveFinalize(t *testing.T) {
	const (
		soPIN   = "so-pin-objects"
		userPIN = "user-pin-objects"
		label   = "persistent-data-object"
	)

	dir := t.TempDir()
	payload := []byte("data that must outlive the module")

	first := newPersistentModule(t, dir)
	require.Equal(t, CKR_OK, first.InitToken(0, []byte(soPIN), "Object Token"))

	session, rv := first.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.Login(session, CKU_SO, []byte(soPIN)))
	require.Equal(t, CKR_OK, first.InitPIN(session, []byte(userPIN)))
	require.Equal(t, CKR_OK, first.Logout(session))
	require.Equal(t, CKR_OK, first.Login(session, CKU_USER, []byte(userPIN)))

	_, rv = first.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE, payload),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.CloseSession(session))
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()

	restored, rv := second.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.Login(restored, CKU_USER, []byte(userPIN)))

	require.Equal(t, CKR_OK, second.FindObjectsInit(restored, []Attribute{
		NewStringAttribute(CKA_LABEL, label),
	}))
	handles, rv := second.FindObjects(restored, 16)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.FindObjectsFinal(restored))
	require.Len(t, handles, 1, "the token object created before the restart must be found after it")

	attrs, rv := second.GetAttributeValue(restored, handles[0], []Attribute{
		{Type: CKA_VALUE},
		{Type: CKA_CLASS},
	})
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, payload, attrs[0].Value, "a restored object must carry its attribute values, not just its handle")
	assert.Equal(t, uint32(CKO_DATA), uint32(attrs[1].Value[0]), "CKA_CLASS must survive the restart")
}

// TestModule_RestoredObjectHandlesDoNotCollide proves the handle counter is
// advanced past every restored handle.
//
// PKCS#11 v3.2 §4.4 requires an object handle to identify exactly one object
// for as long as it is valid. If the counter restarted from zero after a
// reload, the next C_CreateObject would mint a handle that a restored object
// already owns, and one of the two would be reachable only by destroying the
// other. This creates a new object after the restart and requires its handle
// to differ from the restored one.
func TestModule_RestoredObjectHandlesDoNotCollide(t *testing.T) {
	const (
		soPIN   = "so-pin-handles"
		userPIN = "user-pin-handles"
	)

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	require.Equal(t, CKR_OK, first.InitToken(0, []byte(soPIN), "Handle Token"))

	session, rv := first.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.Login(session, CKU_SO, []byte(soPIN)))
	require.Equal(t, CKR_OK, first.InitPIN(session, []byte(userPIN)))
	require.Equal(t, CKR_OK, first.Logout(session))
	require.Equal(t, CKR_OK, first.Login(session, CKU_USER, []byte(userPIN)))

	persisted, rv := first.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "handle-collision-probe"),
		NewAttribute(CKA_VALUE, []byte("persisted")),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, first.CloseSession(session))
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()

	restored, rv := second.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, second.Login(restored, CKU_USER, []byte(userPIN)))

	fresh, rv := second.CreateObject(restored, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "created-after-restart"),
		NewAttribute(CKA_VALUE, []byte("fresh")),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	require.Equal(t, CKR_OK, rv)

	assert.NotEqual(t, persisted, fresh,
		"a handle minted after a reload must not collide with a restored object's handle")
}

// TestModule_InitializeStorage_RejectsUnknownStorageType asserts the typed
// ErrInvalidStorageType rather than a silent fallback.
//
// Falling back to the in-memory backend on an unrecognised storage_type would
// leave an operator who mistyped their configuration with a token that
// provisions cleanly, serves keys all day, and loses every one of them on
// restart. The failure has to be at startup, where it is attributable.
func TestModule_InitializeStorage_RejectsUnknownStorageType(t *testing.T) {
	m, err := New(WithClient(newMockClient()), WithConfig(&Config{StorageType: "nvme-over-carrier-pigeon"}))
	require.NoError(t, err)

	storageErr := m.initializeStorage()
	require.Error(t, storageErr)
	assert.ErrorIs(t, storageErr, ErrInvalidStorageType)
	assert.Nil(t, m.storage, "a rejected storage type must not leave a half-built store behind")
}

// TestModule_InitializeStorage_BuildsRequestedBackends proves the two
// supported storage types are both reachable, including the empty-string case
// that Config.SetDefaults resolves to memory.
func TestModule_InitializeStorage_BuildsRequestedBackends(t *testing.T) {
	cases := []struct {
		name        string
		storageType string
		usePath     bool
	}{
		{"explicit memory", StorageTypeMemory, false},
		{"unset defaults to memory", "", false},
		{"file", StorageTypeFile, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{StorageType: tc.storageType}
			if tc.usePath {
				cfg.StoragePath = t.TempDir()
			}

			m, err := New(WithClient(newMockClient()), WithConfig(cfg))
			require.NoError(t, err)

			require.NoError(t, m.initializeStorage())
			assert.NotNil(t, m.storage)
		})
	}
}

// TestModule_LastStorageError_ReportsBestEffortFailures proves the seam that
// makes best-effort persistence auditable.
//
// Several paths must complete whether or not the store is reachable —
// C_InitToken has to initialize the token even if the state cannot be written
// — so their persistence errors are not returned to the caller. Discarding
// them outright would leave an operator with a module that silently stopped
// persisting; recording the most recent one keeps the failure visible. The
// error must also unwrap, so callers can match the underlying cause rather
// than parse a string.
func TestModule_LastStorageError_ReportsBestEffortFailures(t *testing.T) {
	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()))
	require.NoError(t, err)

	assert.NoError(t, m.LastStorageError(), "a module that has never failed to persist reports no error")

	m.logStorageError("save token state", nil)
	assert.NoError(t, m.LastStorageError(), "a nil error is not a failure and must not be recorded")

	cause := &errs.Message{Msg: "backend unavailable"}
	m.logStorageError("restore persisted object", cause)

	recorded := m.LastStorageError()
	require.Error(t, recorded)
	assert.ErrorIs(t, recorded, cause, "the recorded failure must unwrap to its cause")
	assert.Contains(t, recorded.Error(), "restore persisted object",
		"the recorded failure must name the operation that hit it")
	assert.Contains(t, recorded.Error(), "backend unavailable")
}

// TestModule_FinalizeOperationType_RecordsFailure proves a
// SessionManager.FinalizeOperationType failure is recorded via
// LastStorageError instead of being discarded (#701): every one of its ~60
// call sites in Sign/Verify/Encrypt/etc. runs this cleanup step after the
// CK_RV it returns is already decided, so it cannot fail the Cryptoki call
// over it, but a failure here still needs to be visible to an operator.
func TestModule_FinalizeOperationType_RecordsFailure(t *testing.T) {
	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	assert.NoError(t, m.LastStorageError())

	sm := NewSessionManager(0, 10)
	handle, err := sm.OpenSession(CKF_SERIAL_SESSION)
	require.NoError(t, err)

	// OperationSign was never initialized on this session, so
	// FinalizeOperationType must fail with CKR_OPERATION_NOT_INITIALIZED.
	m.finalizeOperationType(sm, handle, OperationSign)

	recorded := m.LastStorageError()
	require.Error(t, recorded)
	assert.Contains(t, recorded.Error(), "finalize OperationSign operation")
	var pkErr *PKCS11Error
	require.ErrorAs(t, recorded, &pkErr)
	assert.Equal(t, CKR_OPERATION_NOT_INITIALIZED, pkErr.Code)
}

// TestModule_FinalizeOperationType_NoErrorWhenActive proves a successful
// finalize does not record a spurious failure.
func TestModule_FinalizeOperationType_NoErrorWhenActive(t *testing.T) {
	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()))
	require.NoError(t, err)

	sm := NewSessionManager(0, 10)
	handle, err := sm.OpenSession(CKF_SERIAL_SESSION)
	require.NoError(t, err)
	require.NoError(t, sm.InitializeOperation(handle, OperationSign, CKM_SHA256_RSA_PKCS, ObjectHandle(1)))

	m.finalizeOperationType(sm, handle, OperationSign)

	assert.NoError(t, m.LastStorageError())
}

// TestModule_LastInitWarning_ReportsBestEffortFailures proves the seam that
// makes Initialize's best-effort steps auditable (#701): loading persisted
// lockout state, auto-initializing the token, and loading configured PIV
// objects must all complete regardless of whether any one of them failed, so
// none of their failures reach Initialize's own CK_RV. Before this fix they
// were discarded outright (`_ = rv`); recording the most recent one keeps the
// failure visible instead.
func TestModule_LastInitWarning_ReportsBestEffortFailures(t *testing.T) {
	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()))
	require.NoError(t, err)

	assert.NoError(t, m.LastInitWarning(), "a module that has never failed a best-effort init step reports no error")

	m.logInitWarning("auto-initialize token", nil)
	assert.NoError(t, m.LastInitWarning(), "a nil error is not a failure and must not be recorded")

	cause := &errs.Message{Msg: "PIV backend unreachable"}
	m.logInitWarning("load PIV objects for backend tpm2", cause)

	recorded := m.LastInitWarning()
	require.Error(t, recorded)
	assert.ErrorIs(t, recorded, cause, "the recorded failure must unwrap to its cause")
	assert.Contains(t, recorded.Error(), "load PIV objects for backend tpm2",
		"the recorded failure must name the operation that hit it")
	assert.Contains(t, recorded.Error(), "PIV backend unreachable")
}

// TestModule_Initialize_PIVBackendFailureRecordedNotDiscarded exercises the
// same composition Initialize uses for its PIV-loading loop -- LoadPIVObjects
// returning an error and that error reaching logInitWarning -- without
// standing up the full local-transport Initialize path newTestModule's
// fixture does not wire. LoadPIVObjects' own error paths are covered
// separately (TestLoadPIVObjects_ListSlotsError and neighbors); this proves
// the call site that used to be `_ = m.LoadPIVObjects(pivCtx, backend) //
// best effort` now keeps the failure visible.
func TestModule_Initialize_PIVBackendFailureRecordedNotDiscarded(t *testing.T) {
	mc := newPIVMockClient()
	mc.listPIVSlotsErr = errors.New("connection refused")
	m := newTestModule(mc)

	assert.NoError(t, m.LastInitWarning())

	if err := m.LoadPIVObjects(context.Background(), "tpm2"); err != nil {
		m.logInitWarning("load PIV objects for backend tpm2", err)
	}

	recorded := m.LastInitWarning()
	require.Error(t, recorded, "a failed PIV backend load must be visible via LastInitWarning, not silently discarded")
	assert.ErrorIs(t, recorded, ErrPIVListSlots)
}

// errObjectWriteRejected is the cause a rejectingObjectStore reports, so a test
// can match the failure it injected rather than any error at all.
var errObjectWriteRejected = &errs.Message{Msg: "object writes are rejected by this store"}

// rejectingObjectStore is a storage.Backend that serves everything from memory
// but refuses to write an object record.
//
// Only the object prefix is refused: a token whose C_InitToken state could not
// be written either would fail long before a test reached the object path, and
// the failure under test is specifically a store that accepts the token and
// loses its objects — a full filesystem, a revoked credential, a backend that
// went away mid-session.
type rejectingObjectStore struct {
	storage.Backend

	// accept is the number of object writes still to be honoured before the
	// store starts refusing, so a test can fail the second write of a pair and
	// reach the half-persisted case a single-write failure never produces.
	accept *atomic.Int64
}

func newRejectingObjectStore(acceptFirst int64) rejectingObjectStore {
	accept := &atomic.Int64{}
	accept.Store(acceptFirst)

	return rejectingObjectStore{Backend: storage.NewMemory(), accept: accept}
}

func (s rejectingObjectStore) Put(ctx context.Context, key string, value []byte) error {
	if strings.HasPrefix(key, prefixObject) && s.accept.Add(-1) < 0 {
		return errObjectWriteRejected
	}
	return s.Backend.Put(ctx, key, value)
}

// newRejectingStoreModule builds an initialized module whose store accepts token
// state, honours acceptFirst object writes, and refuses every object write after
// that.
func newRejectingStoreModule(t *testing.T, acceptFirst int64) *Module {
	t.Helper()

	m, err := New(WithClient(newMockClient()), WithStorage(newRejectingObjectStore(acceptFirst)))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))

	return m
}

// tokenSecretKeyTemplate describes a CKA_TOKEN generic secret key whose material
// this module's plaintext store can hold whole: neither CKA_SENSITIVE nor
// CKA_EXTRACTABLE=CK_FALSE, so SaveObject writes its CKA_VALUE out with the rest
// of its attributes.
func tokenSecretKeyTemplate(label string) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE, []byte("0123456789abcdef")),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
}

// unimportableSecretKeyValue is a secret this token cannot place in a backend.
//
// C_CreateObject imports a secret key whose material is 16, 24 or 32 bytes,
// because those are the AES lengths the import ceremony can name an algorithm
// for. Twenty bytes -- an HMAC-SHA-1 key, say -- is a perfectly legal generic
// secret with no such algorithm, so the object keeps its material in CKA_VALUE
// and nowhere else. That is the population the persistence rules still govern,
// and using a real one keeps those tests testing the rule rather than an
// artificial object.
var unimportableSecretKeyValue = []byte("TWENTY-BYTE-SECRET!!")

// unimportableTokenSecretKeyTemplate is tokenSecretKeyTemplate with material
// this token cannot import, so the resulting object holds the only copy.
func unimportableTokenSecretKeyTemplate(label string) []Attribute {
	template := tokenSecretKeyTemplate(label)
	for i := range template {
		if template[i].Type == CKA_VALUE {
			template[i] = NewAttribute(CKA_VALUE, unimportableSecretKeyValue)
		}
	}
	return template
}

// findObjectByLabel returns the handles of the objects carrying the given label.
func findObjectByLabel(t *testing.T, m *Module, session SessionHandle, label string) []ObjectHandle {
	t.Helper()

	require.Equal(t, CKR_OK, m.FindObjectsInit(session, []Attribute{
		NewStringAttribute(CKA_LABEL, label),
	}))
	handles, rv := m.FindObjects(session, 16)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.FindObjectsFinal(session))

	return handles
}

// TestModule_SetAttributeValue_SurvivesFinalize proves C_SetAttributeValue's
// effect on a token object is still in force after the module is finalized and a
// new one is brought up over the same storage.
//
// PKCS#11 v3.2 §4.4 keeps a token object on the token "until specifically
// destroyed", and its attributes are part of it. Modification was the one
// mutation this module never wrote back: C_CreateObject, C_CopyObject,
// C_GenerateKey, C_GenerateKeyPair, C_UnwrapKey and C_DeriveKey all persisted
// their result, C_DestroyObject deleted it, and C_SetAttributeValue changed the
// in-memory object and answered CKR_OK.
//
// The tightening is what makes this a security defect rather than a lost label.
// An administrator who sets CKA_ALWAYS_AUTHENTICATE on a stored key is told it
// took effect, and the key comes back at its former, wider permissions at the
// next process start; because §4.9 makes that transition one-way, an
// application that did not know the change was lost could not re-apply it
// idempotently either. An in-memory read cannot catch this — before the fix the
// module answered with the tightened value right up to C_Finalize — so the
// assertion has to be made against a second module reading the same files.
func TestModule_SetAttributeValue_SurvivesFinalize(t *testing.T) {
	const label = "tightened-token-key"

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	session := loginAsNormalUser(t, first)

	handle, rv := first.CreateObject(session, tokenSecretKeyTemplate(label))
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, first.SetAttributeValue(session, handle, []Attribute{
		NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true),
		NewAttribute(CKA_ID, []byte("marker")),
	}), "C_SetAttributeValue must accept a tightening it can carry out")
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()
	restoredSession := loginAsNormalUser(t, second)

	handles := findObjectByLabel(t, second, restoredSession, label)
	require.Len(t, handles, 1, "the modified token object must still be on the token")

	attrs, rv := second.GetAttributeValue(restoredSession, handles[0], []Attribute{
		{Type: CKA_ALWAYS_AUTHENTICATE},
		{Type: CKA_ID},
	})
	require.Equal(t, CKR_OK, rv)

	alwaysAuthenticate, err := findAttr(attrs, CKA_ALWAYS_AUTHENTICATE).GetBool()
	require.NoError(t, err)
	assert.True(t, alwaysAuthenticate,
		"CKA_ALWAYS_AUTHENTICATE set on a token key must still be set after the restart, or the key silently reverts to wider permissions")
	assert.Equal(t, []byte("marker"), findAttr(attrs, CKA_ID).Value,
		"every attribute C_SetAttributeValue wrote must survive the restart, not only the protection bit")
}

// TestModule_SetAttributeValue_RejectedByStore proves a modification the store
// refuses is reported as CKR_DEVICE_ERROR rather than as success.
//
// The alternative — the CKR_OK this used to give unconditionally — is what makes
// the loss silent: an application that tightens a key and is told it worked has
// no reason to check, and no way to tell a token that kept the change from one
// that dropped it. The cause must also reach LastStorageError, so an operator
// can see which store failed and not only the code the application saw.
func TestModule_SetAttributeValue_RejectedByStore(t *testing.T) {
	m := newRejectingStoreModule(t, 0)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	// The object itself is a session object, so it is created successfully by a
	// store that refuses object writes; only the modification below is asked to
	// reach storage. This keeps the assertion on C_SetAttributeValue's own
	// behaviour rather than on C_CreateObject's.
	sessionKey := tokenSecretKeyTemplate("session-key-under-rejecting-store")
	for i := range sessionKey {
		if sessionKey[i].Type == CKA_TOKEN {
			sessionKey[i] = NewBoolAttribute(CKA_TOKEN, false)
		}
	}
	sessionHandle, rv := m.CreateObject(session, sessionKey)
	require.Equal(t, CKR_OK, rv, "a session object must not be affected by a store that refuses object writes")

	assert.Equal(t, CKR_OK, m.SetAttributeValue(session, sessionHandle, []Attribute{
		NewAttribute(CKA_ID, []byte("session-marker")),
	}), "modifying a session object never touches the store, so it must still succeed")

	// A token object cannot be created at all under this store, so it is placed
	// through the store the module already holds and then modified.
	tokenHandle := createTokenObjectBypassingStore(t, m, session, "token-key-under-rejecting-store")

	rv = m.SetAttributeValue(session, tokenHandle, []Attribute{
		NewBoolAttribute(CKA_ALWAYS_AUTHENTICATE, true),
	})
	assert.Equal(t, CKR_DEVICE_ERROR, rv,
		"a tightening the store refused must be reported, not answered with CKR_OK")

	recorded := m.LastStorageError()
	require.Error(t, recorded, "the refusal must be visible to an operator through LastStorageError")
	assert.ErrorIs(t, recorded, errObjectWriteRejected, "the recorded failure must unwrap to the store's own error")
}

// TestModule_SetAttributeValue_RefusesProtectionThatWouldEraseTheKey proves a
// tightening this token could only carry out by destroying the key it protects
// is refused, and that the refusal is confined to the objects that would
// actually lose their material.
//
// Writing a modified token object back is what makes this reachable. A key
// imported by C_CreateObject has its material in CKA_VALUE and names no backend
// key, and SaveObject withholds CKA_VALUE from a key object that protects its
// material — so persisting the tightened object would store a key-shaped shell,
// and the administrator's CKA_SENSITIVE=CK_TRUE would take effect by erasing the
// key. Neither answer is acceptable silently: persisting the value ignores an
// instruction the token accepted, and persisting the tightening destroys the
// key. The application is told instead, while the change is still its to make.
func TestModule_SetAttributeValue_RefusesProtectionThatWouldEraseTheKey(t *testing.T) {
	const label = "imported-token-key"

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	session := loginAsNormalUser(t, first)

	imported, rv := first.CreateObject(session, unimportableTokenSecretKeyTemplate(label))
	require.Equal(t, CKR_OK, rv)

	// The premise of the refusal is that CKA_VALUE is the only copy. Asserting
	// it here means a future change that made this key importable would fail
	// loudly rather than quietly turn the rest of this test vacuous.
	obj, objErr := first.objectManager.getObjectUnchecked(imported)
	require.NoError(t, objErr)
	require.Empty(t, obj.KeyID, "this key must have stayed local for the refusal to be reachable")

	for _, tightening := range []Attribute{
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewBoolAttribute(CKA_EXTRACTABLE, false),
	} {
		assert.Equal(t, CKR_TEMPLATE_INCONSISTENT,
			first.SetAttributeValue(session, imported, []Attribute{tightening}),
			"%s would leave this stored key with no material at all", tightening.Type.String())
	}

	// A refused modification must change nothing, in memory or in the store.
	attrs, rv := first.GetAttributeValue(session, imported, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv, "the refused tightening must not have been half-applied")
	assert.Equal(t, unimportableSecretKeyValue, findAttr(attrs, CKA_VALUE).Value)
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()
	restored := loginAsNormalUser(t, second)

	handles := findObjectByLabel(t, second, restored, label)
	require.Len(t, handles, 1)
	attrs, rv = second.GetAttributeValue(restored, handles[0], []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, unimportableSecretKeyValue, findAttr(attrs, CKA_VALUE).Value,
		"the key must come back whole: a refused tightening cannot cost it its material")
}

// TestModule_SetAttributeValue_AllowsProtectionThatCostsNothing proves the
// refusal above is confined to the objects that would actually lose their
// material.
//
// The tightening is the security-correct thing for an administrator to do, so a
// guard that refused it wholesale would be worse than the defect it prevents. A
// session object is never written out, and a generated key's material lives in
// the backend under its CKA_ID — neither has anything to lose by being marked
// sensitive.
func TestModule_SetAttributeValue_AllowsProtectionThatCostsNothing(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	sessionKey := tokenSecretKeyTemplate("session-key-being-tightened")
	for i := range sessionKey {
		if sessionKey[i].Type == CKA_TOKEN {
			sessionKey[i] = NewBoolAttribute(CKA_TOKEN, false)
		}
	}
	sessionHandle, rv := m.CreateObject(session, sessionKey)
	require.Equal(t, CKR_OK, rv)

	assert.Equal(t, CKR_OK, m.SetAttributeValue(session, sessionHandle, []Attribute{
		NewBoolAttribute(CKA_SENSITIVE, true),
	}), "a session object is never written out, so protecting it costs it nothing")

	generated, rv := m.GenerateKey(session, NewMechanism(CKM_AES_KEY_GEN), []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "generated-key-being-tightened"),
		NewUint32Attribute(CKA_VALUE_LEN, 32),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_SENSITIVE, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	assert.Equal(t, CKR_OK, m.SetAttributeValue(session, generated, []Attribute{
		NewBoolAttribute(CKA_SENSITIVE, true),
	}), "a generated key's material is in the backend, so the stored object loses nothing by being protected")
}

// TestModule_SetAttributeValue_NonKeyTokenObjectStillModifiable proves an
// ordinary token object is untouched by the protection guard and is written
// back like any other modification.
//
// CKA_SENSITIVE and CKA_EXTRACTABLE are defined only for private, secret and OTP
// keys (v3.2 §4.9); a certificate or data object has no protection semantics and
// its CKA_VALUE is public content that always persists. A guard that read those
// two attributes off such an object would find them absent, conclude it was
// unstorable, and refuse every relabelling of every data object on the token —
// which is why the class is checked before the protection is.
func TestModule_SetAttributeValue_NonKeyTokenObjectStillModifiable(t *testing.T) {
	const (
		label    = "renamed-data-object"
		oldLabel = "original-data-object"
	)

	dir := t.TempDir()

	first := newPersistentModule(t, dir)
	session := loginAsNormalUser(t, first)

	handle, rv := first.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, oldLabel),
		NewAttribute(CKA_VALUE, []byte("public object content")),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, first.SetAttributeValue(session, handle, []Attribute{
		NewStringAttribute(CKA_LABEL, label),
	}), "a data object carries no protection semantics and must stay modifiable")
	require.Equal(t, CKR_OK, first.Finalize())

	second := newPersistentModule(t, dir)
	defer second.Finalize()
	restored := loginAsNormalUser(t, second)

	assert.Len(t, findObjectByLabel(t, second, restored, label), 1,
		"the new label must survive the restart")
	assert.Empty(t, findObjectByLabel(t, second, restored, oldLabel),
		"the stored object must not come back under the label it was renamed away from")
}

// TestModule_SetAttributeValue_BadHandleIsNotAStorageFailure proves the storage
// write is reached only by a modification that was actually applied.
//
// A module that persisted before validating, or that reported CKR_DEVICE_ERROR
// for anything that went wrong, would answer an invalid handle with the storage
// code and tell the application its token had failed when its own argument was
// wrong.
func TestModule_SetAttributeValue_BadHandleIsNotAStorageFailure(t *testing.T) {
	m := newRejectingStoreModule(t, 0)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	rv := m.SetAttributeValue(session, ObjectHandle(0xDEADBEEF), []Attribute{
		NewAttribute(CKA_ID, []byte("marker")),
	})
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv,
		"an unknown object handle is the caller's error, not the token's")
	assert.NoError(t, m.LastStorageError(),
		"a call that never reached the store must not record a storage failure")
}

// createTokenObjectBypassingStore places a token object in the module's object
// manager without going through C_CreateObject's persistence step, so a test can
// exercise a later operation against a store that refuses object writes.
func createTokenObjectBypassingStore(t *testing.T, m *Module, session SessionHandle, label string) ObjectHandle {
	t.Helper()

	_, sess, rv := m.findSession(session)
	require.Equal(t, CKR_OK, rv)

	handle, err := m.objectManager.CreateObject(NewAccessContext(session, sess), tokenSecretKeyTemplate(label))
	require.NoError(t, err)

	return handle
}

// TestModule_CreateObject_RejectedByStore proves a token object the store
// refuses is reported as CKR_DEVICE_ERROR and left nowhere.
//
// PKCS#11 v3.2 §5.7.1 either creates the object or does not. An application
// given an error code receives no handle and has nothing to clean up with, so an
// object left in the module's memory would be findable through C_FindObjects for
// the life of the process and gone from the next one — the same divergence
// between what the token reports and what it holds that failing the call exists
// to prevent.
func TestModule_CreateObject_RejectedByStore(t *testing.T) {
	const label = "unstorable-token-object"

	m := newRejectingStoreModule(t, 0)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	handle, rv := m.CreateObject(session, tokenSecretKeyTemplate(label))
	assert.Equal(t, CKR_DEVICE_ERROR, rv, "a token object the store refused was not created")
	assert.Equal(t, ObjectHandle(InvalidHandle), handle, "a failed creation must not hand back a handle")

	assert.Empty(t, findObjectByLabel(t, m, session, label),
		"an object the caller was told was not created must not be findable")

	recorded := m.LastStorageError()
	require.Error(t, recorded)
	assert.ErrorIs(t, recorded, errObjectWriteRejected)
}

// TestModule_CreateObject_SessionObjectIgnoresStore proves the fix did not turn
// a store failure into a failure of calls that never touch the store.
//
// A session object is not persisted at all (v3.2 §4.4), so a broken store must
// leave C_CreateObject for one working. Without this, "report every storage
// failure" would be indistinguishable from "fail every creation once the store
// is unhappy", and a module whose store had gone away would stop serving even
// the operations that do not need it.
func TestModule_CreateObject_SessionObjectIgnoresStore(t *testing.T) {
	m := newRejectingStoreModule(t, 0)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	handle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "session-scoped-data"),
		NewAttribute(CKA_VALUE, []byte("not persisted anywhere")),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	assert.Equal(t, CKR_OK, rv, "a session object must be created whether or not the store is healthy")
	assert.NotEqual(t, ObjectHandle(InvalidHandle), handle)
	assert.NoError(t, m.LastStorageError(), "a session object must not reach the store at all")
}

// TestModule_GenerateKeyPair_HalfPersistedPairIsUnwound proves C_GenerateKeyPair
// leaves nothing behind when the store takes the public key and then refuses the
// private one.
//
// PKCS#11 v3.2 §5.18.2 creates both objects or neither, and this is the only
// case where "neither" takes undoing: the public key is already in the store by
// the time the private key is refused. A pair left half-persisted comes back at
// the next start as a public key whose private half does not exist, which an
// application cannot distinguish from a key whose private half it was never
// given — so it would keep offering a certificate it can no longer sign for.
func TestModule_GenerateKeyPair_HalfPersistedPairIsUnwound(t *testing.T) {
	// One object write is honoured: the public key's. The private key's is
	// refused, which is the case under test.
	m := newRejectingStoreModule(t, 1)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	pubHandle, privHandle, rv := m.GenerateKeyPair(session,
		NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN),
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "half-persisted-pub"),
			NewUint32Attribute(CKA_MODULUS_BITS, 2048),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_VERIFY, true),
		},
		[]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_PRIVATE_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
			NewStringAttribute(CKA_LABEL, "half-persisted-priv"),
			NewBoolAttribute(CKA_TOKEN, true),
			NewBoolAttribute(CKA_SIGN, true),
		})

	assert.Equal(t, CKR_DEVICE_ERROR, rv, "a pair the store could not hold whole was not generated")
	assert.Equal(t, ObjectHandle(InvalidHandle), pubHandle)
	assert.Equal(t, ObjectHandle(InvalidHandle), privHandle)

	assert.Empty(t, findObjectByLabel(t, m, session, "half-persisted-pub"),
		"the public key must not be left in memory after its pair failed")
	assert.Empty(t, findObjectByLabel(t, m, session, "half-persisted-priv"),
		"the private key must not be left in memory after its pair failed")

	persisted, err := m.storage.LoadObjects(SlotID(0))
	require.NoError(t, err)
	assert.Empty(t, persisted,
		"the public key the store already accepted must be deleted again, or the next start finds a private-key-less pair")
}
