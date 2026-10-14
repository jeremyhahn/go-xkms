package vtpm

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrors_NameTheTenantAndUnwrapTheCause pins what an operator reads in a
// log line (the tenant or binary at fault) and that every wrapping error
// keeps its cause reachable through errors.Is.
func TestErrors_NameTheTenantAndUnwrapTheCause(t *testing.T) {
	cause := errors.New("cause")
	tests := []struct {
		name    string
		err     error
		message string
		cause   error
	}{
		{"binary", &BinaryError{Binary: "/opt/swtpm", Err: os.ErrNotExist}, `vtpm: Config.Binary "/opt/swtpm": file does not exist`, os.ErrNotExist},
		{"state key", &StateKeyError{Tenant: "acme", Err: cause}, `vtpm: state key for tenant "acme": cause`, cause},
		{"start", &StartError{Tenant: "acme", Err: ErrNotRunning}, `vtpm: starting the vTPM for tenant "acme": ` + ErrNotRunning.Error(), ErrNotRunning},
		{"stop", &StopError{Tenant: "acme", Err: cause}, `vtpm: stopping the vTPM for tenant "acme": cause`, cause},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.message, tt.err.Error())
			assert.ErrorIs(t, tt.err, tt.cause)
			assert.NotErrorIs(t, tt.err, ErrManagerClosed)
		})
	}
}

// TestStateKeySizeError_ReportsTheSizeAndTheWant pins the size error, which
// has no cause to unwrap.
func TestStateKeySizeError_ReportsTheSizeAndTheWant(t *testing.T) {
	err := &StateKeySizeError{Tenant: "acme", Size: 9}
	assert.Equal(t, `vtpm: state key for tenant "acme" is 9 bytes, want 32`, err.Error())
	assert.Nil(t, errors.Unwrap(err))
}
