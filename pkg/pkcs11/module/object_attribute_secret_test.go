package module

import (
	"errors"
	"testing"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttribute_ReleaseWipesValue proves Release zeroes the Go-side bytes in
// place, not just the slice header, so the C-boundary copy is the only one left.
func TestAttribute_ReleaseWipesValue(t *testing.T) {
	backing := []byte("secret-value")
	attrs := []Attribute{{Type: CKA_VALUE, Value: backing}, {Type: CKA_LABEL}}

	ReleaseAttributes(attrs)

	assert.Nil(t, attrs[0].Value)
	assert.Equal(t, make([]byte, len("secret-value")), backing, "backing array must be zeroed")
	attrs[0].Release() // idempotent
}

// TestAttribute_ReleaseDestroysSecret proves a sealed value is destroyed by
// Release and can no longer be borrowed.
func TestAttribute_ReleaseDestroysSecret(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("sealed-value"))
	require.NoError(t, err)
	attr := Attribute{Type: CKA_VALUE, Secret: buf}

	assert.Equal(t, len("sealed-value"), attr.ValueLen())
	require.NoError(t, attr.WithValue(func(v []byte) error {
		assert.Equal(t, []byte("sealed-value"), v)
		return nil
	}))

	attr.Release()
	assert.Nil(t, attr.Secret)
	assert.Zero(t, attr.ValueLen())
	assert.Error(t, buf.WithBytes(func([]byte) error { return nil }), "Release must destroy the sealed buffer")
}

// TestAttribute_WithValuePropagatesError proves a callback error comes back
// unchanged for both storage forms.
func TestAttribute_WithValuePropagatesError(t *testing.T) {
	want := errors.New("copy failed")
	plain := Attribute{Value: []byte("x")}
	assert.ErrorIs(t, plain.WithValue(func([]byte) error { return want }), want)

	buf, err := secure.NewBufferFromBytes([]byte("x"))
	require.NoError(t, err)
	sealed := Attribute{Secret: buf}
	defer sealed.Release()
	assert.ErrorIs(t, sealed.WithValue(func([]byte) error { return want }), want)
}
