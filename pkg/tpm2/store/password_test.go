// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearPassword_NewPassword(t *testing.T) {
	password := []byte("test-password")

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify Bytes returns the password
	assert.Equal(t, password, p.Bytes())

	// String must never return the password
	assert.Equal(t, types.PasswordRedacted, p.String())
	assert.NotContains(t, fmt.Sprintf("%v %s", p, p), "test-password")

	// WithBytes lends the password
	var seen []byte
	require.NoError(t, p.WithBytes(func(b []byte) error {
		seen = append(seen, b...)
		return nil
	}))
	assert.Equal(t, password, seen)
}

func TestClearPassword_NewPassword_DifferentValue(t *testing.T) {
	password := []byte("clear-password")

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify Bytes returns the password
	assert.Equal(t, password, p.Bytes())

	// String must never return the password
	assert.Equal(t, types.PasswordRedacted, p.String())
}

func TestClearPassword_Empty(t *testing.T) {
	password := []byte{}

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify Bytes returns empty slice
	assert.Empty(t, p.Bytes())

	// String is redacted even when there is nothing to hide
	assert.Equal(t, types.PasswordRedacted, p.String())

	// WithBytes lends nil: an empty UserAuth means no authentication
	called := false
	require.NoError(t, p.WithBytes(func(b []byte) error {
		called = true
		assert.Empty(t, b)
		return nil
	}))
	assert.True(t, called)
}

func TestClearPassword_Nil(t *testing.T) {
	var password []byte

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify Bytes returns nil
	assert.Nil(t, p.Bytes())

	// String is redacted even when there is nothing to hide
	assert.Equal(t, types.PasswordRedacted, p.String())

	// WithBytes lends nil: an empty UserAuth means no authentication
	called := false
	require.NoError(t, p.WithBytes(func(b []byte) error {
		called = true
		assert.Empty(t, b)
		return nil
	}))
	assert.True(t, called)
}

func TestClearPassword_Clear(t *testing.T) {
	password := []byte("sensitive-password")
	passwordCopy := make([]byte, len(password))
	copy(passwordCopy, password)

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify password is present
	assert.Equal(t, passwordCopy, p.Bytes())

	// Clear the password
	p.Clear()

	// Verify all bytes are zeroed
	for i, b := range p.Bytes() {
		assert.Equal(t, byte(0), b, "byte at index %d should be 0", i)
	}
}

func TestClearPassword_ClearEmpty(t *testing.T) {
	password := []byte{}

	p, err := NewPassword(password)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Clear should not panic on empty password
	p.Clear()

	// Verify Bytes still returns empty slice
	assert.Empty(t, p.Bytes())
}

func TestRequiredPassword_NewRequiredPassword(t *testing.T) {
	p := NewRequiredPassword()
	require.NotNil(t, p)
}

func TestRequiredPassword_Bytes(t *testing.T) {
	p := NewRequiredPassword()

	// Bytes should return nil for RequiredPassword
	assert.Nil(t, p.Bytes())
}

func TestRequiredPassword_String(t *testing.T) {
	p := NewRequiredPassword()

	assert.Equal(t, types.PasswordRedacted, p.String())
}

func TestRequiredPassword_WithBytes(t *testing.T) {
	p := NewRequiredPassword()

	// WithBytes must fail closed without calling the callback
	err := p.WithBytes(func([]byte) error {
		t.Fatal("callback must not run for a required password")
		return nil
	})
	assert.Equal(t, ErrPasswordRequired, err)
}

func TestRequiredPassword_Clear_ViaInterface(t *testing.T) {
	p := NewRequiredPassword()

	// Clear should not panic - it's a no-op
	p.Clear()

	// Verify state is unchanged
	assert.Nil(t, p.Bytes())
}

func TestRequiredPassword_Clear_DirectAccess(t *testing.T) {
	// Test the RequiredPassword.Clear method directly
	p := &RequiredPassword{}

	// Clear should not panic - it's a no-op
	p.Clear()

	// Verify state - should still be nil
	assert.Nil(t, p.Bytes())
}

func TestDEFAULT_PASSWORD(t *testing.T) {
	// Verify the default password constant
	assert.Equal(t, "changeme", DEFAULT_PASSWORD)
}
