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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Object destruction driven by session and token lifecycle events.
//
// Two PKCS#11 rules decide when the library destroys objects the application
// never asked it to destroy, and both are one-sided: destroying too little
// leaves key material reachable after the credential that protected it is
// gone, destroying too much loses an application's data. Each test below
// therefore checks a survivor as well as a casualty.

// TestModule_Logout_DestroysPrivateSessionObjectsOnly encodes PKCS#11 v3.2
// §5.6.10: C_Logout "logs a user out from a token ... Any of the application's
// handles to private objects become invalid after this."
//
// The public session object is the control. A logout that cleared the whole
// session-object table would pass any test that only checked the private
// object was gone, while silently discarding data the application is entitled
// to keep — CKA_PRIVATE is what gates access, and a public object was never
// protected by the login in the first place.
func TestModule_Logout_DestroysPrivateSessionObjectsOnly(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	private, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "private-session-object"),
		NewAttribute(CKA_VALUE, []byte("protected by the login")),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, true),
	})
	require.Equal(t, CKR_OK, rv)

	public, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "public-session-object"),
		NewAttribute(CKA_VALUE, []byte("readable without a login")),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
	})
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.Logout(session))

	_, rv = m.GetAttributeValue(session, private, []Attribute{{Type: CKA_VALUE}})
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv,
		"C_Logout must invalidate handles to private objects (v3.2 §5.6.10)")

	attrs, rv := m.GetAttributeValue(session, public, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv, "a public session object must survive C_Logout")
	assert.Equal(t, []byte("readable without a login"), attrs[0].Value)
}

// TestModule_InitToken_DestroysOnlyDestroyableObjects encodes the destruction
// half of PKCS#11 v3.2 §5.5.7: C_InitToken "destroys all objects that can be
// destroyed" on the token.
//
// The qualifier is the rule. CKA_DESTROYABLE is CK_FALSE on objects an
// administrator has pinned to the token — a device identity certificate, say —
// and re-initializing the token must leave those in place. An implementation
// that read §5.5.7 as "destroys all objects" would wipe exactly the material
// that was marked as not-to-be-wiped, and there is no way to get it back.
func TestModule_InitToken_DestroysOnlyDestroyableObjects(t *testing.T) {
	const soPIN = "so-pin-initoken"

	m := initializeTestModule(t)
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.InitToken(0, []byte(soPIN), "Destroy Token"))

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_SO, []byte(soPIN)))

	destroyable, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "destroyable"),
		NewAttribute(CKA_VALUE, []byte("ordinary token data")),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_DESTROYABLE, true),
	})
	require.Equal(t, CKR_OK, rv)

	pinned, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "pinned"),
		NewAttribute(CKA_VALUE, []byte("administratively pinned")),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_DESTROYABLE, false),
	})
	require.Equal(t, CKR_OK, rv)

	// C_InitToken refuses to run while a session is open (v3.2 §5.5.7), which
	// is why the session is closed rather than merely logged out.
	require.Equal(t, CKR_OK, m.CloseSession(session))
	require.Equal(t, CKR_OK, m.InitToken(0, []byte(soPIN), "Destroy Token"))

	after, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(after, CKU_SO, []byte(soPIN)))

	_, rv = m.GetAttributeValue(after, destroyable, []Attribute{{Type: CKA_VALUE}})
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, rv,
		"C_InitToken must destroy every destroyable object on the token (v3.2 §5.5.7)")

	attrs, rv := m.GetAttributeValue(after, pinned, []Attribute{{Type: CKA_VALUE}})
	require.Equal(t, CKR_OK, rv, "CKA_DESTROYABLE=CK_FALSE must survive C_InitToken")
	assert.Equal(t, []byte("administratively pinned"), attrs[0].Value)
}

// TestObjectManager_DestroyAllDestroyableObjects_LeavesOtherSlotsAlone proves
// the destruction is scoped to one token.
//
// A module presenting several slots holds every object in one manager, so the
// slot filter is the only thing keeping C_InitToken on slot 0 from wiping slot
// 1. That is not reachable through the module's single-slot public surface,
// so it is exercised directly on the object manager, where the filter lives.
func TestObjectManager_DestroyAllDestroyableObjects_LeavesOtherSlotsAlone(t *testing.T) {
	om := NewObjectManager()

	target := &Object{
		Handle:        ObjectHandle(101),
		SlotID:        SlotID(0),
		Class:         CKO_DATA,
		IsToken:       true,
		IsDestroyable: true,
		Attributes:    map[AttributeType][]byte{CKA_VALUE: []byte("slot 0")},
	}
	neighbour := &Object{
		Handle:        ObjectHandle(102),
		SlotID:        SlotID(1),
		Class:         CKO_DATA,
		IsToken:       true,
		IsDestroyable: true,
		Attributes:    map[AttributeType][]byte{CKA_VALUE: []byte("slot 1")},
	}

	require.NoError(t, om.AddObject(target))
	require.NoError(t, om.AddObject(neighbour))

	destroyed := om.DestroyAllDestroyableObjects(SlotID(0))
	assert.Equal(t, []ObjectHandle{ObjectHandle(101)}, destroyed,
		"only the named slot's objects may be destroyed, and their handles are reported so storage can be cleared")

	_, err := om.getObjectUnchecked(ObjectHandle(101))
	assert.Error(t, err, "the destroyed object must be gone from the manager")

	survivor, err := om.getObjectUnchecked(ObjectHandle(102))
	require.NoError(t, err, "another slot's object must be untouched")
	assert.Equal(t, []byte("slot 1"), survivor.Attributes[CKA_VALUE],
		"a surviving object must keep its material; zeroizing it would be as bad as destroying it")
}

// TestObjectManager_DestroyPrivateSessionObjects_LeavesOtherSessionsAlone
// proves the logout sweep is scoped to the session that logged out.
//
// The login state is token-wide, but the object table is not: session objects
// belong to the session that created them and die with it (v3.2 §4.4). A sweep
// that walked the whole table would destroy another session's private objects
// on a logout that had nothing to do with them.
func TestObjectManager_DestroyPrivateSessionObjects_LeavesOtherSessionsAlone(t *testing.T) {
	om := NewObjectManager()

	const (
		loggingOut = SessionHandle(7)
		untouched  = SessionHandle(8)
	)

	mine := &Object{Handle: ObjectHandle(201), Class: CKO_DATA, IsPrivate: true}
	minePublic := &Object{Handle: ObjectHandle(202), Class: CKO_DATA, IsPrivate: false}
	theirs := &Object{Handle: ObjectHandle(203), Class: CKO_DATA, IsPrivate: true}

	for _, obj := range []*Object{mine, minePublic, theirs} {
		require.NoError(t, om.AddObject(obj))
	}

	om.mu.Lock()
	om.trackSessionObject(loggingOut, mine.Handle)
	om.trackSessionObject(loggingOut, minePublic.Handle)
	om.trackSessionObject(untouched, theirs.Handle)
	om.mu.Unlock()

	om.DestroyPrivateSessionObjects(loggingOut)

	_, err := om.getObjectUnchecked(mine.Handle)
	assert.Error(t, err, "the logging-out session's private object must be destroyed")

	_, err = om.getObjectUnchecked(minePublic.Handle)
	assert.NoError(t, err, "the logging-out session's public object must survive")

	_, err = om.getObjectUnchecked(theirs.Handle)
	assert.NoError(t, err, "another session's private object is not this logout's business")
}
