// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearPassword_NewPassword(t *testing.T) {
	password := []byte("test-password")

	p := NewPassword(password)
	require.NotNil(t, p)

	// Verify Bytes returns the password
	assert.Equal(t, password, p.Bytes())

	// Verify String returns the password as string
	str, err := p.String()
	assert.NoError(t, err)
	assert.Equal(t, "test-password", str)
}

func TestClearPassword_NewClearPassword(t *testing.T) {
	password := []byte("clear-password")

	p := NewClearPassword(password)
	require.NotNil(t, p)

	// Verify Bytes returns the password
	assert.Equal(t, password, p.Bytes())

	// Verify String returns the password as string
	str, err := p.String()
	assert.NoError(t, err)
	assert.Equal(t, "clear-password", str)
}

func TestClearPassword_Empty(t *testing.T) {
	password := []byte{}

	p := NewPassword(password)
	require.NotNil(t, p)

	// Verify Bytes returns empty slice
	assert.Empty(t, p.Bytes())

	// Verify String returns empty string
	str, err := p.String()
	assert.NoError(t, err)
	assert.Equal(t, "", str)
}

func TestClearPassword_Nil(t *testing.T) {
	var password []byte

	p := NewPassword(password)
	require.NotNil(t, p)

	// Verify Bytes returns nil
	assert.Nil(t, p.Bytes())

	// Verify String returns empty string
	str, err := p.String()
	assert.NoError(t, err)
	assert.Equal(t, "", str)
}

func TestClearPassword_Clear(t *testing.T) {
	password := []byte("sensitive-password")
	passwordCopy := make([]byte, len(password))
	copy(passwordCopy, password)

	p := NewPassword(password)
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

	p := NewPassword(password)
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

	// String should return ErrPasswordRequired
	str, err := p.String()
	assert.Error(t, err)
	assert.Equal(t, ErrPasswordRequired, err)
	assert.Equal(t, "", str)
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
