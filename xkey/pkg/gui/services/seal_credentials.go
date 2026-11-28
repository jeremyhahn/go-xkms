package services

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// destroySealCredentials releases creds' secret and returns the release
// error. Since go-enclave v0.11.1 the secret is an enclave.Sealed interface
// and CredentialsFor returns the zero SealCredentials (nil Secret) for an
// empty password, which is the normal case for a hardware-backed strategy
// such as TPM2; calling creds.Secret.Destroy() on it dereferences nil.
func destroySealCredentials(creds xkms.SealCredentials) error {
	if creds.Secret == nil {
		return nil
	}
	return creds.Secret.Destroy()
}
