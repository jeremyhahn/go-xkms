// Package store provides password implementations
package store

import (
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Re-export password constant
const DEFAULT_PASSWORD = store.DEFAULT_PASSWORD

// Re-export password types
type (
	ClearPassword    = store.ClearPassword
	RequiredPassword = store.RequiredPassword
)

// NewPassword creates a new clear text password for TPM key authentication.
func NewPassword(password []byte) types.Password {
	return store.NewPassword(password)
}

// NewClearPassword is an alias for NewPassword for backward compatibility.
// Deprecated: Use NewPassword instead.
func NewClearPassword(password []byte) types.Password {
	return NewPassword(password)
}

// NewRequiredPassword creates a password placeholder that returns ErrPasswordRequired
func NewRequiredPassword() types.Password {
	return store.NewRequiredPassword()
}
