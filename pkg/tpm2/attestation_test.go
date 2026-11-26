//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestParseEventLog was deleted rather than un-skipped. Its body was nothing
// but a skip call: it asserted nothing and could never fail, and reviving it
// would have meant reading the host's
// /sys/kernel/security/tpm*/binary_bios_measurements, which no unit test may
// depend on.
//
// Event log parsing is covered exhaustively and host-independently in
// eventlog_test.go, which parses synthetic TCG logs from t.TempDir():
// TestParseEventLog_BootSequence (a multi-event, multi-bank boot sequence
// asserted field by field), TestParseEventLog_TruncatedData and
// TestParseEventLog_TruncatedUnknownAlgorithmDigest (malformed input),
// TestParseEventLog_Success, TestParseEventLog_EmptyFile and
// TestParseEventLog_FileNotFound.

// ---------------------------------------------------------------------------
// CertifyKey tests (from attestation_certify_test.go)
// ---------------------------------------------------------------------------

// noopTransport is a minimal transport.TPM implementation for unit tests
// that only need to pass nil checks without executing TPM commands.
type noopTransport struct{}

func (tr *noopTransport) Send(input []byte) ([]byte, error) {
	return nil, ErrNotInitialized
}

func TestCertifyKey_NotInitialized(t *testing.T) {
	// Create a TPM2 instance with nil transport to simulate
	// an uninitialized TPM
	tpmObj := &TPM2{
		transport: nil,
	}

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}
	nonce := []byte("test-nonce")

	result, err := tpmObj.CertifyKey(attrs, nonce, nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCertifyKey_IAKNotProvisioned(t *testing.T) {
	// Create a TPM2 instance with a non-nil transport placeholder
	// but with nil IAK attributes to simulate IAK not provisioned.
	tpmObj := &TPM2{
		transport: &noopTransport{},
		iakAttrs:  nil,
	}

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}
	nonce := []byte("test-nonce")

	result, err := tpmObj.CertifyKey(attrs, nonce, nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrIAKNotProvisioned)
}

func TestCertifyKey_NilKeyAttributes(t *testing.T) {
	// Verify that nil key attributes returns ErrInvalidKeyAttributes
	tpmObj := &TPM2{
		transport: &noopTransport{},
		iakAttrs:  &types.KeyAttributes{CN: "iak"},
	}

	result, err := tpmObj.CertifyKey(nil, []byte("nonce"), nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}
