//go:build integration && tpm2

package integration

import (
	"testing"

	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// setupTPM2 creates a TPM2 instance for testing
// This is a convenience wrapper around createTPM2Instance for tests that
// don't need special setup
func setupTPM2(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()
	return createTPM2Instance(t)
}
