package tpm2

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestPasswordFromSecretValue_NilIsEmptyPassword proves an unconfigured
// secret yields a usable, empty password rather than nil.
func TestPasswordFromSecretValue_NilIsEmptyPassword(t *testing.T) {
	pw, err := passwordFromSecretValue(nil)
	if err != nil {
		t.Fatalf("passwordFromSecretValue(nil): %v", err)
	}
	if pw == nil {
		t.Fatal("password is nil, want non-nil empty password")
	}
	defer pw.Clear()
	if len(pw.Bytes()) != 0 {
		t.Errorf("Bytes() = %q, want empty", pw.Bytes())
	}
}

// TestPasswordFromSecretValue_UnresolvedRefused proves a configured but
// never-resolved secret is refused instead of being used as the password.
func TestPasswordFromSecretValue_UnresolvedRefused(t *testing.T) {
	pw, err := passwordFromSecretValue(&types.SecretValue{Raw: "credential://tpm-pw"})
	var unresolved *types.SecretReferenceUnresolvedError
	if !errors.As(err, &unresolved) {
		t.Fatalf("err = %v, want *SecretReferenceUnresolvedError", err)
	}
	if pw != nil {
		t.Errorf("password = %v, want nil", pw)
	}
}
