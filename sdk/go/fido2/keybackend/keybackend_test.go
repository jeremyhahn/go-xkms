package keybackend_test

import (
	"testing"

	pkgkeybackend "github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/keybackend"
)

// TestTPM2AttestingBackendIsTheAuthenticatorType proves the sdk alias is the
// authenticator type itself, so xkey can hold the backend without pkg/.
func TestTPM2AttestingBackendIsTheAuthenticatorType(t *testing.T) {
	var b *keybackend.TPM2AttestingBackend = (*pkgkeybackend.TPM2AttestingBackend)(nil)
	if b != nil {
		t.Fatal("nil conversion must stay nil")
	}
}
