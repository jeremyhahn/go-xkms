// Copyright (C) 2025 go-xkms authors
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published
//    by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

package module

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// faultBackend wraps a real memory backend and fails a chosen operation, so a
// test can prove a persistence failure is reported rather than swallowed under
// CKR_OK. Only the operations the persistence-error tests need are switchable.
type faultBackend struct {
	storage.Backend
	failPut    bool
	failDelete bool
}

func newFaultBackend() *faultBackend {
	return &faultBackend{Backend: storage.NewMemory()}
}

var errInjectedStorage = errors.New("injected storage failure")

func (f *faultBackend) Put(ctx context.Context, key string, value []byte) error {
	if f.failPut {
		return errInjectedStorage
	}
	return f.Backend.Put(ctx, key, value)
}

func (f *faultBackend) Delete(ctx context.Context, key string) error {
	if f.failDelete {
		return errInjectedStorage
	}
	return f.Backend.Delete(ctx, key)
}

// newModuleWithBackend builds an initialized module whose persistence is the
// supplied backend, so a test can flip a fault on after setup.
func newModuleWithBackend(t *testing.T, backend storage.Backend) *Module {
	t.Helper()
	m, err := New(WithClient(newMockClient()), WithStorage(backend), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))
	t.Cleanup(func() { m.Finalize() })
	return m
}

// C21: C_InitPIN / C_SetPIN must not report success when the new PIN was never
// written — a restart would silently present the old PIN. §5.5.7/§5.5.8 list
// CKR_DEVICE_ERROR for exactly this.

func TestInitPIN_ReportsDeviceErrorWhenPersistFails(t *testing.T) {
	fb := newFaultBackend()
	m := newModuleWithBackend(t, fb)

	require.Equal(t, CKR_OK, m.InitToken(0, []byte("so-pin-init"), "Fault Token"))

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_SO, []byte("so-pin-init")))

	fb.failPut = true
	rv = m.InitPIN(session, []byte("user-pin-init"))
	require.Equal(t, CKR_DEVICE_ERROR, rv,
		"a PIN that could not be persisted must not be reported as set")
}

// C22: C_InitToken must not report success if a destroyable object's persistent
// delete failed — the object would reappear at the next C_Initialize under a
// token the administrator believes empty.

func TestInitToken_ReportsDeviceErrorWhenObjectDeleteFails(t *testing.T) {
	fb := newFaultBackend()
	m := newModuleWithBackend(t, fb)

	// Give the token a persisted (token) object to destroy on re-init.
	require.Equal(t, CKR_OK, m.InitToken(0, []byte("so-pin-a"), "Fault Token"))
	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_SO, []byte("so-pin-a")))
	require.Equal(t, CKR_OK, m.InitPIN(session, []byte("user-pin-a")))
	require.Equal(t, CKR_OK, m.Logout(session))
	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-a")))

	_, rv = m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA)),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewStringAttribute(CKA_LABEL, "doomed"),
		NewAttribute(CKA_VALUE, []byte("payload")),
	})
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.CloseSession(session))

	// Re-initializing (with the existing SO PIN) must destroy that object; make
	// the persistent delete fail.
	fb.failDelete = true
	rv = m.InitToken(0, []byte("so-pin-a"), "Fault Token")
	require.Equal(t, CKR_DEVICE_ERROR, rv,
		"C_InitToken must fail if a destroyable object could not be removed from the store")
}

// C20: a corrupt or unreadable persisted object record must surface as an error
// from LoadObjects rather than being silently dropped, so C_Initialize can
// refuse rather than present a token missing one of its objects.

func TestLoadObjects_SurfacesCorruptRecord(t *testing.T) {
	backend := storage.NewMemory()
	ctx := context.Background()
	require.NoError(t, backend.Put(ctx, prefixObject+"corrupt", []byte("{not valid json")))

	ms := NewModuleStorage(backend)
	_, err := ms.LoadObjects(0)
	require.Error(t, err, "a record that will not unmarshal must be reported, not skipped")
}
