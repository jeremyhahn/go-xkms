//go:build integration

package integration

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpm2lib "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// setupTPM2 creates a TPM2 instance for testing
// This is a convenience wrapper around createTPM2Instance for tests that
// don't need special setup
func setupTPM2(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()
	return createTPM2Instance(t)
}

// loadKey loads the persisted key pair keyAttrs names and returns its
// transient handle and name, flushed when the test ends. CreateRSA and
// CreateECDSA flush their transient handle before returning, so
// keyAttrs.TPMAttributes.Handle no longer references a loaded object;
// a command that takes the key's handle, such as TPM2_RSA_Encrypt, needs
// the key loaded again, as every operation in pkg/tpm2 does.
func loadKey(t *testing.T, tpmInstance tpm2lib.TrustedPlatformModule, keyAttrs *types.KeyAttributes) (tpm2.TPMHandle, tpm2.TPM2BName) {
	t.Helper()

	loaded, err := tpmInstance.LoadKeyPair(keyAttrs, nil, nil)
	if err != nil {
		t.Fatalf("Failed to load key pair %s: %v", keyAttrs.CN, err)
	}
	t.Cleanup(func() { tpmInstance.Flush(loaded.ObjectHandle) })
	return loaded.ObjectHandle, loaded.Name
}
