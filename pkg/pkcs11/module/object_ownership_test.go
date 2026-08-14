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

package module

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests in this file cover session-object ownership: what it governs (lifetime)
// and, just as importantly, what it does not (visibility).
//
// A CKA_TOKEN=false object is scoped to the application, not to the single
// session that created it. One Cryptoki instance serves exactly one
// application, so every session an ObjectManager knows about belongs to that
// same application and must be able to reach the object; only its lifetime is
// tied to the creating session, which is why ownership is recorded at all.
//
// The rule was briefly inverted here, and the cost was concrete: OpenSSL's
// pkcs11-provider copies a token private key into a session object with
// C_CopyObject on one session from its pool and then issues C_SignInit for it on
// another, so every private-key operation it drove came back
// CKR_KEY_HANDLE_INVALID. SoftHSM, the reference implementation, resolves that
// same handle across sessions without complaint.

// dataTemplate builds a CKO_DATA creation template with the given label and
// CKA_TOKEN setting. Data objects are used throughout this file because they
// exercise the object layer without pulling in a backend or a mechanism.
func dataTemplate(label string, tokenObject bool) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, label),
		NewAttribute(CKA_VALUE, []byte(label)),
		NewBoolAttribute(CKA_TOKEN, tokenObject),
		NewBoolAttribute(CKA_PRIVATE, false),
	}
}

// findHandles runs a complete C_FindObjects cycle for the session and returns
// every handle the search yielded.
func findHandles(t *testing.T, om *ObjectManager, ctx AccessContext, template []Attribute) []ObjectHandle {
	t.Helper()

	require.NoError(t, om.FindObjectsInit(ctx, template))

	var found []ObjectHandle
	for {
		batch, err := om.FindObjects(ctx.Session, 8)
		require.NoError(t, err)
		if len(batch) == 0 {
			break
		}
		found = append(found, batch...)
	}

	require.NoError(t, om.FindObjectsFinal(ctx.Session))
	return found
}

// requireHandleInvalid asserts that err is CKR_OBJECT_HANDLE_INVALID. An object
// the session may not see must be indistinguishable from a handle that was
// never allocated, so this is the only acceptable error on an unauthorized
// read path.
func requireHandleInvalid(t *testing.T, err error, context string) {
	t.Helper()

	var pkcsErr *PKCS11Error
	require.True(t, errors.As(err, &pkcsErr), "%s: expected a *PKCS11Error, got %v", context, err)
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, pkcsErr.Code,
		"%s: an object the session may not see must be reported exactly like a nonexistent handle", context)
}

// TestSessionObjectIsVisibleToEverySessionOfTheApplication exercises every read
// and write path that resolves a handle from a session other than the one that
// created the object.
//
// This is the shape of the pkcs11-provider flow that a per-session visibility
// rule broke: create or copy an object on one session of the pool, then use it
// from another. All six calls must succeed.
func TestSessionObjectIsVisibleToEverySessionOfTheApplication(t *testing.T) {
	om := NewObjectManager()

	creator := fullAccessCtx(SessionHandle(1))
	other := fullAccessCtx(SessionHandle(2))

	handle, err := om.CreateObject(creator, dataTemplate("shared-session-object", false))
	require.NoError(t, err)

	searchTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "shared-session-object"),
	}

	t.Run("FindObjectsInit matches it", func(t *testing.T) {
		assert.Contains(t, findHandles(t, om, other, searchTemplate), handle)
	})

	t.Run("GetObjectFor resolves it", func(t *testing.T) {
		obj, err := om.GetObjectFor(other, handle)
		require.NoError(t, err)
		assert.Equal(t, handle, obj.Handle)
	})

	t.Run("GetAttributeValue reads it", func(t *testing.T) {
		values, err := om.GetAttributeValue(other, handle, []Attribute{{Type: CKA_LABEL}})
		require.NoError(t, err)
		require.Len(t, values, 1)
		assert.Equal(t, "shared-session-object", string(values[0].Value))
	})

	t.Run("CopyObject duplicates it", func(t *testing.T) {
		copied, err := om.CopyObject(other, handle, nil)
		require.NoError(t, err)
		assert.NotEqual(t, handle, copied)
	})

	t.Run("SetAttributeValue modifies it", func(t *testing.T) {
		require.NoError(t, om.SetAttributeValue(other, handle,
			[]Attribute{NewStringAttribute(CKA_LABEL, "relabelled")}))

		values, err := om.GetAttributeValue(creator, handle, []Attribute{{Type: CKA_LABEL}})
		require.NoError(t, err)
		require.Len(t, values, 1)
		assert.Equal(t, "relabelled", string(values[0].Value),
			"the creating session must observe the other session's write")
	})

	t.Run("DestroyObject destroys it", func(t *testing.T) {
		require.NoError(t, om.DestroyObject(other, handle))

		_, err := om.GetObjectFor(creator, handle)
		requireHandleInvalid(t, err, "GetObjectFor after destroy")
	})
}

// TestSessionObjectRemainsVisibleToItsOwner covers the ordinary case the rule
// above must not disturb: a session that creates a working object goes on to
// find, read, modify and destroy it itself.
func TestSessionObjectRemainsVisibleToItsOwner(t *testing.T) {
	om := NewObjectManager()
	owner := fullAccessCtx(SessionHandle(1))

	handle, err := om.CreateObject(owner, dataTemplate("mine", false))
	require.NoError(t, err)

	found := findHandles(t, om, owner, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "mine"),
	})
	assert.Contains(t, found, handle, "the creating session must find its own session object")

	obj, err := om.GetObjectFor(owner, handle)
	require.NoError(t, err)
	assert.Equal(t, handle, obj.Handle)

	require.NoError(t, om.SetAttributeValue(owner, handle, []Attribute{NewStringAttribute(CKA_LABEL, "still mine")}))
	require.NoError(t, om.DestroyObject(owner, handle))
}

// TestTokenObjectIsVisibleAcrossSessions pins the plainest sharing rule: a
// CKA_TOKEN object belongs to the token, not to a session, so every session on
// the slot must see it whoever created it.
func TestTokenObjectIsVisibleAcrossSessions(t *testing.T) {
	om := NewObjectManager()

	creator := fullAccessCtx(SessionHandle(1))
	observer := fullAccessCtx(SessionHandle(2))

	handle, err := om.CreateObject(creator, dataTemplate("shared-token-object", true))
	require.NoError(t, err)

	found := findHandles(t, om, observer, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "shared-token-object"),
	})
	assert.Contains(t, found, handle, "a token object created in session A must be visible to session B")

	obj, err := om.GetObjectFor(observer, handle)
	require.NoError(t, err)
	assert.Equal(t, handle, obj.Handle)

	values, err := om.GetAttributeValue(observer, handle, []Attribute{{Type: CKA_LABEL}})
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, "shared-token-object", string(values[0].Value))
}

// TestUnownedSessionObjectIsVisibleToEverySession covers the objects AddObject
// inserts with no owning session: restored token objects and objects mirroring
// hardware slot state, some of which carry CKA_TOKEN = CK_FALSE. They are
// module-scoped — nothing destroys them when a session closes — so every session
// on the slot must reach them, which is what keeps PIV slot mirroring and
// persisted-object restore working.
func TestUnownedSessionObjectIsVisibleToEverySession(t *testing.T) {
	om := NewObjectManager()

	mirrored := NewObject(CKO_DATA)
	mirrored.SetAttribute(CKA_TOKEN, boolAttributeValue(false))
	mirrored.SetAttribute(CKA_PRIVATE, boolAttributeValue(false))
	mirrored.SetAttribute(CKA_LABEL, []byte("mirrored-slot-object"))
	mirrored.SetAttribute(CKA_VALUE, []byte("mirrored"))
	require.False(t, mirrored.IsToken, "the fixture must be a session-scoped object for this test to mean anything")

	require.NoError(t, om.AddObject(mirrored))

	searchTemplate := []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "mirrored-slot-object"),
	}

	for _, session := range []SessionHandle{1, 2, 3} {
		ctx := fullAccessCtx(session)

		assert.Contains(t, findHandles(t, om, ctx, searchTemplate), mirrored.Handle,
			"an object with no owning session is module-scoped and must be found by session %d", session)

		obj, err := om.GetObjectFor(ctx, mirrored.Handle)
		require.NoError(t, err, "session %d must be able to resolve an unowned object", session)
		assert.Equal(t, mirrored.Handle, obj.Handle)
	}
}

// TestOwnershipIndexIsClearedOnDestroy proves the reverse index does not retain
// entries for handles that no longer exist. A stale entry would make a later
// object inherit a dead session's ownership and become invisible to the session
// that actually created it.
func TestOwnershipIndexIsClearedOnDestroy(t *testing.T) {
	om := NewObjectManager()
	owner := fullAccessCtx(SessionHandle(1))

	t.Run("DestroyObject clears the entry", func(t *testing.T) {
		handle, err := om.CreateObject(owner, dataTemplate("destroyed", false))
		require.NoError(t, err)
		require.NoError(t, om.DestroyObject(owner, handle))

		om.mu.RLock()
		_, stillIndexed := om.objectOwner[handle]
		om.mu.RUnlock()
		assert.False(t, stillIndexed, "a destroyed handle must not remain in the ownership index")
	})

	t.Run("DestroySessionObjects clears the entries", func(t *testing.T) {
		session := SessionHandle(7)
		ctx := fullAccessCtx(session)

		first, err := om.CreateObject(ctx, dataTemplate("closing-a", false))
		require.NoError(t, err)
		second, err := om.CreateObject(ctx, dataTemplate("closing-b", false))
		require.NoError(t, err)

		om.DestroySessionObjects(session)

		om.mu.RLock()
		_, firstIndexed := om.objectOwner[first]
		_, secondIndexed := om.objectOwner[second]
		indexSize := len(om.objectOwner)
		om.mu.RUnlock()

		assert.False(t, firstIndexed)
		assert.False(t, secondIndexed)
		assert.Zero(t, indexSize, "closing the only session with objects must leave the index empty")
	})

	t.Run("DestroyPrivateSessionObjects clears only the private entries", func(t *testing.T) {
		session := SessionHandle(9)
		ctx := fullAccessCtx(session)

		publicHandle, err := om.CreateObject(ctx, dataTemplate("public-survivor", false))
		require.NoError(t, err)

		privateHandle, err := om.CreateObject(ctx, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
			NewStringAttribute(CKA_LABEL, "private-casualty"),
			NewAttribute(CKA_VALUE, []byte("secret")),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_PRIVATE, true),
		})
		require.NoError(t, err)

		om.DestroyPrivateSessionObjects(session)

		om.mu.RLock()
		_, publicIndexed := om.objectOwner[publicHandle]
		_, privateIndexed := om.objectOwner[privateHandle]
		om.mu.RUnlock()

		assert.True(t, publicIndexed, "a public session object survives C_Logout and keeps its owner")
		assert.False(t, privateIndexed, "a destroyed private session object must leave the ownership index")

		// The survivor must still be usable by its owner.
		_, err = om.GetObjectFor(ctx, publicHandle)
		assert.NoError(t, err)
	})
}

// TestUnauthorizedHandleIsIndistinguishableFromNonexistent checks that a caller
// cannot probe for objects it may not see by comparing error codes. A live
// handle on another token and a handle that was never allocated must both come
// back as CKR_OBJECT_HANDLE_INVALID.
func TestUnauthorizedHandleIsIndistinguishableFromNonexistent(t *testing.T) {
	om := NewObjectManager()

	onSlotZero := fullAccessCtx(SessionHandle(1))
	onSlotOne := fullAccessCtx(SessionHandle(2))
	onSlotOne.Slot = 1

	live, err := om.CreateObject(onSlotZero, dataTemplate("probe-target", false))
	require.NoError(t, err)

	nonexistent := live + 1000

	_, foreignErr := om.GetObjectFor(onSlotOne, live)
	_, missingErr := om.GetObjectFor(onSlotOne, nonexistent)

	var foreign, missing *PKCS11Error
	require.True(t, errors.As(foreignErr, &foreign))
	require.True(t, errors.As(missingErr, &missing))
	assert.Equal(t, missing.Code, foreign.Code,
		"another token's object and a nonexistent handle must report the same error code")
	assert.Equal(t, CKR_OBJECT_HANDLE_INVALID, foreign.Code)
}

// TestCanAccessRejectsBadInput exercises the negative edges of the visibility
// check directly: a nil object, an object on a different slot, and a private
// object seen by an unauthenticated session must all be rejected, whichever
// session created them.
func TestCanAccessRejectsBadInput(t *testing.T) {
	om := NewObjectManager()
	owner := fullAccessCtx(SessionHandle(1))

	handle, err := om.CreateObject(owner, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewStringAttribute(CKA_LABEL, "private-object"),
		NewAttribute(CKA_VALUE, []byte("secret")),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, true),
	})
	require.NoError(t, err)

	obj, err := om.GetObjectFor(owner, handle)
	require.NoError(t, err)

	assert.False(t, owner.CanAccess(nil),
		"a nil object must never be accessible")

	otherSlot := owner
	otherSlot.Slot = 1
	assert.False(t, otherSlot.CanAccess(obj),
		"an object on another token must never be accessible")

	unauthenticated := AccessContext{Session: owner.Session, ReadWrite: true}
	assert.False(t, unauthenticated.CanAccess(obj),
		"a private object must stay invisible until the user logs in")

	assert.True(t, owner.CanAccess(obj),
		"an authenticated session must reach a private object on its own token")

	otherSession := fullAccessCtx(SessionHandle(2))
	assert.True(t, otherSession.CanAccess(obj),
		"another session of the same application must reach it too")
}
