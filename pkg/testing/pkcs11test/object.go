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

package pkcs11test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunObjectTests verifies Section 5.7 Object Management of the PKCS#11 v3.0 spec.
// It exercises C_CreateObject, C_CopyObject, C_DestroyObject, C_GetAttributeValue,
// C_SetAttributeValue, C_FindObjectsInit/C_FindObjects/C_FindObjectsFinal, and
// C_GetObjectSize.
func (s *Suite) RunObjectTests(t *testing.T) {
	t.Run("C_CreateObject", s.testCreateObject)
	t.Run("C_CopyObject", s.testCopyObject)
	t.Run("C_DestroyObject", s.testDestroyObject)
	t.Run("C_GetAttributeValue", s.testGetAttributeValue)
	t.Run("C_SetAttributeValue", s.testSetAttributeValue)
	t.Run("C_FindObjects", s.testFindObjects)
	t.Run("C_GetObjectSize", s.testGetObjectSize)
}

// testCreateObject verifies C_CreateObject for data objects, key objects, and
// error handling with invalid session handles.
func (s *Suite) testCreateObject(t *testing.T) {

	t.Run("create_data_object_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "test-data-create"),
			module.NewAttribute(module.CKA_VALUE, []byte("hello-world")),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
			module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
			module.NewBoolAttribute(module.CKA_COPYABLE, true),
			module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
		}

		handle, rv := m.CreateObject(sh, template)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "CreateObject data should succeed")

		if handle == 0 {
			t.Fatal("expected non-zero object handle from CreateObject")
		}
	})

	t.Run("create_key_object_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		handle := createSecretKeyObject(t, m, sh)
		if handle == 0 {
			t.Fatal("expected non-zero object handle for secret key")
		}
	})

	t.Run("invalid_session_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)
		template := []module.Attribute{
			module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
			module.NewStringAttribute(module.CKA_LABEL, "should-fail"),
			module.NewAttribute(module.CKA_VALUE, []byte("data")),
			module.NewBoolAttribute(module.CKA_TOKEN, false),
		}

		_, rv := m.CreateObject(invalidSession, template)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"CreateObject with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testCopyObject verifies C_CopyObject for valid copies and invalid handle errors.
func (s *Suite) testCopyObject(t *testing.T) {

	t.Run("copy_valid_object_succeeds_with_new_handle", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		srcHandle := createDataObject(t, m, sh, "copy-source")

		copyTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "copy-destination"),
		}

		newHandle, rv := m.CopyObject(sh, srcHandle, copyTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "CopyObject should succeed")

		if newHandle == 0 {
			t.Fatal("expected non-zero handle for copied object")
		}
		if newHandle == srcHandle {
			t.Fatalf("copied object handle %d must differ from source handle %d",
				newHandle, srcHandle)
		}

		// Verify the copy has the new label
		getTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, ""),
		}
		attrs, rv := m.GetAttributeValue(sh, newHandle, getTemplate)
		requireRV(t, module.CKR_OK, rv, "GetAttributeValue on copied object should succeed")

		if len(attrs) == 0 {
			t.Fatal("expected at least one attribute in GetAttributeValue result")
		}
		gotLabel := string(attrs[0].Value)
		if gotLabel != "copy-destination" {
			t.Fatalf("copied object label: got %q, want %q", gotLabel, "copy-destination")
		}
	})

	t.Run("copy_invalid_object_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidHandle := module.ObjectHandle(0xBADF00D)

		_, rv := m.CopyObject(sh, invalidHandle, nil)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"CopyObject with invalid handle should return CKR_OBJECT_HANDLE_INVALID")
	})
}

// testDestroyObject verifies C_DestroyObject for valid objects, invalid handles,
// and double-destroy semantics.
func (s *Suite) testDestroyObject(t *testing.T) {

	t.Run("destroy_valid_object_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		handle := createDataObject(t, m, sh, "destroy-me")

		rv := m.DestroyObject(sh, handle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "DestroyObject should succeed for valid object")
	})

	t.Run("destroy_invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidHandle := module.ObjectHandle(0xBADF00D)

		rv := m.DestroyObject(sh, invalidHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"DestroyObject with invalid handle should return CKR_OBJECT_HANDLE_INVALID")
	})

	t.Run("destroy_same_object_twice_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		handle := createDataObject(t, m, sh, "destroy-twice")

		rv := m.DestroyObject(sh, handle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first DestroyObject should succeed")

		rv = m.DestroyObject(sh, handle)
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"second DestroyObject should return CKR_OBJECT_HANDLE_INVALID")
	})
}

// testGetAttributeValue verifies C_GetAttributeValue retrieves the correct label
// and fails on invalid handles.
func (s *Suite) testGetAttributeValue(t *testing.T) {

	t.Run("get_label_returns_correct_value", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		const expectedLabel = "get-attr-test"
		handle := createDataObject(t, m, sh, expectedLabel)

		getTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, ""),
		}

		attrs, rv := m.GetAttributeValue(sh, handle, getTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "GetAttributeValue should succeed")

		if len(attrs) != 1 {
			t.Fatalf("expected 1 attribute, got %d", len(attrs))
		}
		gotLabel := string(attrs[0].Value)
		if gotLabel != expectedLabel {
			t.Fatalf("CKA_LABEL: got %q, want %q", gotLabel, expectedLabel)
		}
	})

	t.Run("invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidHandle := module.ObjectHandle(0xBADF00D)

		getTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, ""),
		}

		_, rv := m.GetAttributeValue(sh, invalidHandle, getTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"GetAttributeValue with invalid handle should return CKR_OBJECT_HANDLE_INVALID")
	})
}

// testSetAttributeValue verifies C_SetAttributeValue modifies a modifiable
// attribute and fails on invalid handles.
func (s *Suite) testSetAttributeValue(t *testing.T) {

	t.Run("set_modifiable_attribute_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		handle := createDataObject(t, m, sh, "original-label")

		const updatedLabel = "updated-label"
		setTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, updatedLabel),
		}

		rv := m.SetAttributeValue(sh, handle, setTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "SetAttributeValue should succeed on modifiable object")

		// Verify the label was updated
		getTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, ""),
		}
		attrs, rv := m.GetAttributeValue(sh, handle, getTemplate)
		requireRV(t, module.CKR_OK, rv, "GetAttributeValue after set should succeed")

		if len(attrs) != 1 {
			t.Fatalf("expected 1 attribute, got %d", len(attrs))
		}
		gotLabel := string(attrs[0].Value)
		if gotLabel != updatedLabel {
			t.Fatalf("CKA_LABEL after set: got %q, want %q", gotLabel, updatedLabel)
		}
	})

	t.Run("invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidHandle := module.ObjectHandle(0xBADF00D)

		setTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, "whatever"),
		}

		rv := m.SetAttributeValue(sh, invalidHandle, setTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"SetAttributeValue with invalid handle should return CKR_OBJECT_HANDLE_INVALID")
	})
}

// testFindObjects verifies C_FindObjectsInit, C_FindObjects, and C_FindObjectsFinal
// including the full search cycle, label matching, empty template, and error states.
func (s *Suite) testFindObjects(t *testing.T) {

	t.Run("init_find_final_cycle_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		createDataObject(t, m, sh, "find-cycle-obj")

		rv := m.FindObjectsInit(sh, nil)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "FindObjectsInit should succeed")

		_, rv = m.FindObjects(sh, 10)
		requireRV(t, module.CKR_OK, rv, "FindObjects should succeed")

		rv = m.FindObjectsFinal(sh)
		requireRV(t, module.CKR_OK, rv, "FindObjectsFinal should succeed")
	})

	t.Run("find_by_label_finds_matching_objects", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		const targetLabel = "find-by-label-target"
		createDataObject(t, m, sh, targetLabel)
		createDataObject(t, m, sh, "find-by-label-other")

		searchTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, targetLabel),
		}

		rv := m.FindObjectsInit(sh, searchTemplate)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "FindObjectsInit with label filter should succeed")

		handles, rv := m.FindObjects(sh, 10)
		requireRV(t, module.CKR_OK, rv, "FindObjects should succeed")

		if len(handles) != 1 {
			t.Fatalf("expected 1 matching object, got %d", len(handles))
		}

		// Verify the found object has the correct label
		getTemplate := []module.Attribute{
			module.NewStringAttribute(module.CKA_LABEL, ""),
		}
		attrs, rv := m.GetAttributeValue(sh, handles[0], getTemplate)
		requireRV(t, module.CKR_OK, rv, "GetAttributeValue on found object should succeed")

		if len(attrs) == 0 {
			t.Fatal("expected at least one attribute")
		}
		gotLabel := string(attrs[0].Value)
		if gotLabel != targetLabel {
			t.Fatalf("found object label: got %q, want %q", gotLabel, targetLabel)
		}

		rv = m.FindObjectsFinal(sh)
		requireRV(t, module.CKR_OK, rv, "FindObjectsFinal should succeed")
	})

	t.Run("find_with_empty_template_returns_all_objects", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		createDataObject(t, m, sh, "all-obj-1")
		createDataObject(t, m, sh, "all-obj-2")
		createSecretKeyObject(t, m, sh)

		// Empty template matches all objects
		rv := m.FindObjectsInit(sh, []module.Attribute{})
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "FindObjectsInit with empty template should succeed")

		handles, rv := m.FindObjects(sh, 100)
		requireRV(t, module.CKR_OK, rv, "FindObjects should succeed")

		if len(handles) < 3 {
			t.Fatalf("expected at least 3 objects, got %d", len(handles))
		}

		rv = m.FindObjectsFinal(sh)
		requireRV(t, module.CKR_OK, rv, "FindObjectsFinal should succeed")
	})

	t.Run("find_objects_without_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		_, rv := m.FindObjects(sh, 10)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OPERATION_NOT_INITIALIZED, rv,
			"FindObjects without FindObjectsInit should return CKR_OPERATION_NOT_INITIALIZED")
	})

	t.Run("double_find_init_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.FindObjectsInit(sh, nil)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "first FindObjectsInit should succeed")

		rv = m.FindObjectsInit(sh, nil)
		requireRV(t, module.CKR_OPERATION_ACTIVE, rv,
			"second FindObjectsInit should return CKR_OPERATION_ACTIVE")

		// Clean up the active operation
		rv = m.FindObjectsFinal(sh)
		requireRV(t, module.CKR_OK, rv, "FindObjectsFinal cleanup should succeed")
	})
}

// testGetObjectSize verifies C_GetObjectSize returns a size for valid objects
// and fails on invalid handles.
func (s *Suite) testGetObjectSize(t *testing.T) {

	t.Run("returns_size_for_valid_object", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		handle := createDataObject(t, m, sh, "size-test-obj")

		size, rv := m.GetObjectSize(sh, handle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "GetObjectSize should succeed for valid object")

		if size == 0 {
			t.Fatal("expected non-zero size for data object with value and label")
		}
	})

	t.Run("invalid_handle_fails", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)
		invalidHandle := module.ObjectHandle(0xBADF00D)

		_, rv := m.GetObjectSize(sh, invalidHandle)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OBJECT_HANDLE_INVALID, rv,
			"GetObjectSize with invalid handle should return CKR_OBJECT_HANDLE_INVALID")
	})
}
