// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package localtpm

import (
	"errors"
	"io/fs"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen_RequiresItsDependencies(t *testing.T) {
	_, err := Open(Params{})
	assert.ErrorIs(t, err, ErrNoTPM)
}

func TestOpenDevice_RequiresADataDirectory(t *testing.T) {
	_, err := OpenDevice(DeviceParams{Device: "/dev/tpmrm0"})
	assert.ErrorIs(t, err, ErrNoDataDir)
	_, err = OpenHost(DeviceParams{}, nil)
	assert.ErrorIs(t, err, ErrNoDataDir)
}

func TestOpenDevice_MissingDeviceIsADeviceError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm")
	_, err := OpenDevice(DeviceParams{DataDir: t.TempDir(), Device: missing})
	var devErr *DeviceError
	require.ErrorAs(t, err, &devErr)
	assert.Equal(t, missing, devErr.Device)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Contains(t, err.Error(), missing)
}

func TestBuildError_WrapsItsCause(t *testing.T) {
	cause := errors.New("store unavailable")
	err := error(&BuildError{Err: cause})
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "store unavailable")
}

func TestSealedObjectOperations_RequireAName(t *testing.T) {
	l := &Policies{}
	assert.ErrorIs(t, l.SealObject(t.Context(), "", "", nil), ErrObjectNameRequired)
	_, err := l.UnsealObject(t.Context(), "")
	assert.ErrorIs(t, err, ErrObjectNameRequired)
	assert.ErrorIs(t, l.DeleteObject(t.Context(), ""), ErrObjectNameRequired)
}

func TestLock_ReportsTheSharedTPMsRefusal(t *testing.T) {
	refused := errors.New("tpm shutting down")
	l := &Policies{lockFn: func() (func(), error) { return nil, refused }}
	assert.ErrorIs(t, l.Assign(t.Context(), "key", "k1", ""), refused)
	assert.ErrorIs(t, l.Unassign(t.Context(), "key", "k1"), refused)
	_, err := l.AutoUnsealPolicy(t.Context())
	assert.ErrorIs(t, err, refused)
	_, err = l.UnsealObject(t.Context(), "obj")
	assert.ErrorIs(t, err, refused)
	assert.ErrorIs(t, l.SealObject(t.Context(), "obj", "", []byte("x")), refused)
	assert.ErrorIs(t, l.DeleteObject(t.Context(), "obj"), refused)
}

func TestAssign_RefusesAnUnknownObjectKind(t *testing.T) {
	l := &Policies{}
	assert.Error(t, l.Assign(t.Context(), "bogus", "k1", ""))
	assert.Error(t, l.Unassign(t.Context(), "bogus", "k1"))
}

func TestPolicyAPI_ReportsTheSharedTPMsRefusal(t *testing.T) {
	refused := errors.New("tpm shutting down")
	l := &Policies{lockFn: func() (func(), error) { return nil, refused }}
	_, err := l.TPMPolicyList(t.Context(), nil)
	assert.ErrorIs(t, err, refused)
	assert.ErrorIs(t, l.TPMPolicyDelete(t.Context(), nil), refused)
}

func TestOpenDevice_DialsATPMOverTCP(t *testing.T) {
	// A tcp:// device is dialled, not stat'ed: nothing listens on the port,
	// so the open fails in the transport rather than as a missing device.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	_, err = OpenDevice(DeviceParams{DataDir: t.TempDir(), Device: "tcp://" + addr})
	require.Error(t, err)
	var devErr *DeviceError
	assert.False(t, errors.As(err, &devErr), "a TCP TPM is not a device file")
}
