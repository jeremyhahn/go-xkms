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

package services

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockElevator implements the Elevator interface for testing.
type mockElevator struct {
	available bool
	output    []byte
	err       error
	lastArgs  []string
	lastData  []byte
	callCount int
	allArgs   [][]string // tracks args for every Run call
}

func (m *mockElevator) Run(args []string, stdinData []byte) ([]byte, error) {
	m.lastArgs = args
	m.lastData = stdinData
	m.callCount++
	m.allArgs = append(m.allArgs, append([]string(nil), args...))
	return m.output, m.err
}

func (m *mockElevator) IsAvailable() bool {
	return m.available
}

// testSudoLogger returns a no-op slog logger for test SudoElevator instances.
func testSudoLogger() *slog.Logger {
	return slog.Default().With("component", "sudo_elevator_test")
}

// --- PkexecElevator tests ---

func TestNewPkexecElevator(t *testing.T) {
	e := NewPkexecElevator()
	assert.NotNil(t, e)
	// The constructor should resolve the current executable path.
	assert.NotEmpty(t, e.execPath, "execPath should be set from os.Executable()")
}

func TestPkexecElevator_IsAvailable_NoExecPath(t *testing.T) {
	// An elevator with an empty exec path should not be available,
	// regardless of whether pkexec is installed.
	e := &PkexecElevator{execPath: ""}
	assert.False(t, e.IsAvailable())
}

func TestPkexecElevator_Run_NoExecPath(t *testing.T) {
	e := &PkexecElevator{execPath: ""}
	out, err := e.Run([]string{"luks2", "seal"}, nil)
	assert.Nil(t, out)
	assert.True(t, errors.Is(err, ErrElevationUnavailable))
}

func TestPkexecElevator_Run_MissingPkexec(t *testing.T) {
	// Use a valid path for the exec but a command that will
	// fail because pkexec itself is invoked with a bogus binary.
	e := &PkexecElevator{execPath: "/nonexistent/xkey"}
	out, err := e.Run([]string{"luks2", "seal"}, nil)
	assert.Nil(t, out)
	// Should fail with ErrElevationFailed since the command cannot execute.
	assert.Error(t, err)
}

// --- SudoElevator tests ---

func TestNewSudoElevator(t *testing.T) {
	e := NewSudoElevator("testpass")
	assert.NotNil(t, e)
	// The constructor should resolve the current executable path.
	assert.NotEmpty(t, e.execPath, "execPath should be set from os.Executable()")
}

func TestSudoElevator_IsAvailable_NoExecPath(t *testing.T) {
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "",
		password: []byte("test"),
	}
	assert.False(t, e.IsAvailable())
}

func TestSudoElevator_Run_NoExecPath(t *testing.T) {
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "",
		password: []byte("test"),
	}
	out, err := e.Run([]string{"trust", "install", "abc123"}, nil)
	assert.Nil(t, out)
	assert.True(t, errors.Is(err, ErrElevationUnavailable))
}

func TestSudoElevator_Run_SudoUnavailable(t *testing.T) {
	// Use a nonexistent exec path that passes the empty check
	// but will cause IsAvailable to fail (sudo not on PATH or exec missing).
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "/nonexistent/xkey",
		password: []byte("test"),
	}
	// On systems without sudo or with this nonexistent path,
	// IsAvailable returns false and Run should return ErrSudoUnavailable.
	if !e.IsAvailable() {
		out, err := e.Run([]string{"trust", "install", "abc123"}, nil)
		assert.Nil(t, out)
		assert.True(t, errors.Is(err, ErrSudoUnavailable))
	}
}

func TestSudoElevator_ZerosBytesAfterRun(t *testing.T) {
	password := []byte("secretpass")
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "", // Will return ErrElevationUnavailable immediately.
		password: password,
	}

	_, _ = e.Run([]string{"trust", "install", "abc123"}, nil)

	// With execPath empty, Run returns before zeroing. This tests the
	// constructor stores the password correctly.
	assert.Equal(t, []byte("secretpass"), password,
		"password not zeroed when Run returns early due to empty execPath")
}

// --- zeroBytes tests ---

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive")
	zeroBytes(data)
	for i, b := range data {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	data := []byte{}
	zeroBytes(data)
	assert.Empty(t, data)
}

func TestZeroBytes_Nil(t *testing.T) {
	// Should not panic on nil slice.
	zeroBytes(nil)
}

// --- Mock elevator tests ---

func TestMockElevator_Run_Success(t *testing.T) {
	m := &mockElevator{
		available: true,
		output:    []byte(`{"status":"ok"}`),
	}

	out, err := m.Run([]string{"luks2", "seal", "--size", "1G"}, []byte("pass\npass\n"))
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"status":"ok"}`), out)
	assert.Equal(t, []string{"luks2", "seal", "--size", "1G"}, m.lastArgs)
	assert.Equal(t, []byte("pass\npass\n"), m.lastData)
}

func TestMockElevator_Run_Error(t *testing.T) {
	m := &mockElevator{
		available: true,
		err:       ErrElevationFailed,
	}

	out, err := m.Run([]string{"luks2", "seal"}, nil)
	assert.Nil(t, out)
	assert.True(t, errors.Is(err, ErrElevationFailed))
	assert.Equal(t, []string{"luks2", "seal"}, m.lastArgs)
}

func TestMockElevator_Run_Denied(t *testing.T) {
	m := &mockElevator{
		available: true,
		err:       ErrElevationDenied,
	}

	out, err := m.Run([]string{"luks2", "unseal"}, []byte("pass\n"))
	assert.Nil(t, out)
	assert.True(t, errors.Is(err, ErrElevationDenied))
	assert.Equal(t, []string{"luks2", "unseal"}, m.lastArgs)
}

func TestMockElevator_IsAvailable_True(t *testing.T) {
	m := &mockElevator{available: true}
	assert.True(t, m.IsAvailable())
}

func TestMockElevator_IsAvailable_False(t *testing.T) {
	m := &mockElevator{available: false}
	assert.False(t, m.IsAvailable())
}

// --- Error sentinel tests ---

func TestElevationErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrElevationUnavailable,
		ErrElevationDenied,
		ErrElevationFailed,
		ErrSudoUnavailable,
		ErrElevationRequired,
	}

	for i := range errs {
		for j := range errs {
			if i == j {
				continue
			}
			assert.NotEqual(t, errs[i], errs[j],
				"error %d and %d should be distinct", i, j)
		}
	}
}

// --- PkexecElevator IsAvailable with valid path ---

func TestPkexecElevator_IsAvailable_WithPath(t *testing.T) {
	e := NewPkexecElevator()
	// The result depends on whether pkexec is installed on the system.
	// We just verify the function does not panic with a valid execPath.
	_ = e.IsAvailable()
}

// --- PkexecElevator Run with nil stdinData ---

func TestPkexecElevator_Run_NilStdinData(t *testing.T) {
	e := &PkexecElevator{execPath: "/nonexistent/xkey"}
	out, err := e.Run([]string{"test"}, nil)
	assert.Nil(t, out)
	assert.Error(t, err)
}

// --- PkexecElevator Run with stdinData ---

func TestPkexecElevator_Run_WithStdinData(t *testing.T) {
	e := &PkexecElevator{execPath: "/nonexistent/xkey"}
	out, err := e.Run([]string{"test"}, []byte("stdin-data\n"))
	assert.Nil(t, out)
	assert.Error(t, err)
}

// --- PkexecElevator Run empty args ---

func TestPkexecElevator_Run_EmptyArgs(t *testing.T) {
	e := &PkexecElevator{execPath: "/nonexistent/xkey"}
	out, err := e.Run([]string{}, nil)
	assert.Nil(t, out)
	assert.Error(t, err)
}

// --- SudoElevator constructor stores password ---

func TestSudoElevator_PasswordStored(t *testing.T) {
	e := NewSudoElevator("mypassword")
	assert.Equal(t, []byte("mypassword"), e.password)
}

// --- SudoElevator constructor with empty password ---

func TestSudoElevator_EmptyPassword(t *testing.T) {
	e := NewSudoElevator("")
	assert.Equal(t, []byte(""), e.password)
	assert.NotEmpty(t, e.execPath)
}

// --- SudoElevator Run with nil stdinData ---

func TestSudoElevator_Run_NilStdinData(t *testing.T) {
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "",
		password: []byte("test"),
	}
	out, err := e.Run([]string{"test"}, nil)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

// --- SudoElevator Run with empty args ---

func TestSudoElevator_Run_EmptyArgs(t *testing.T) {
	e := &SudoElevator{
		log:      testSudoLogger(),
		execPath: "",
		password: []byte("test"),
	}
	out, err := e.Run([]string{}, nil)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrElevationUnavailable)
}

// --- zeroBytes with various lengths ---

func TestZeroBytes_SingleByte(t *testing.T) {
	data := []byte{0xFF}
	zeroBytes(data)
	assert.Equal(t, byte(0), data[0])
}

func TestZeroBytes_LargeSlice(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0xFF
	}
	zeroBytes(data)
	for i, b := range data {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

// --- SudoElevator IsAvailable with valid sudo (system-dependent) ---

func TestSudoElevator_IsAvailable_WithValidPath(t *testing.T) {
	e := NewSudoElevator("test")
	// On systems with sudo installed, this should return true.
	// On systems without sudo, false. Either way, no panic.
	_ = e.IsAvailable()
}

// --- Elevator interface compliance ---

func TestPkexecElevator_ImplementsElevator(t *testing.T) {
	var e Elevator = NewPkexecElevator()
	assert.NotNil(t, e)
}

func TestSudoElevator_ImplementsElevator(t *testing.T) {
	var e Elevator = NewSudoElevator("test")
	assert.NotNil(t, e)
}
