package tpm2

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nvExtendResponse builds a TPM response: header (tag, size, code) followed
// by body. size is written as given so a test can make it disagree with the
// response's real length.
func nvExtendResponse(tag uint16, size uint32, code uint32, body ...byte) []byte {
	rsp := binary.BigEndian.AppendUint16(nil, tag)
	rsp = binary.BigEndian.AppendUint32(rsp, size)
	rsp = binary.BigEndian.AppendUint32(rsp, code)
	return append(rsp, body...)
}

// sendNVExtend runs nvExtendExecute under a password session against a
// transport that answers with rsp.
func sendNVExtend(t *testing.T, rsp []byte) (*lockoutTransport, error) {
	t.Helper()
	tr := &lockoutTransport{rsp: rsp}
	err := nvExtendExecute(
		tr,
		tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x01500040),
			Name:   tpm2.TPM2BName{Buffer: []byte("nv-index-name")},
		},
		[]byte("extend-data"),
	)
	return tr, err
}

// TestNvExtendExecute_RefusesMalformedResponse proves every response the
// parser cannot trust is refused as ErrMalformedNVExtendResponse. A size
// field smaller than the header used to slice the response backwards and
// panic.
func TestNvExtendExecute_RefusesMalformedResponse(t *testing.T) {
	tests := []struct {
		name string
		rsp  []byte
	}{
		{"shorter than a header", []byte{0x80, 0x02, 0x00, 0x00}},
		{"unknown tag", nvExtendResponse(0x1234, tpmHeaderSize, 0)},
		{"size below the header", nvExtendResponse(tpmSTSessions, 0, 0)},
		{"size beyond the response", nvExtendResponse(tpmSTSessions, 64, 0)},
		{"no parameter size", nvExtendResponse(tpmSTSessions, tpmHeaderSize+2, 0, 0x00, 0x00)},
		{"parameter size beyond the response", nvExtendResponse(tpmSTSessions, tpmHeaderSize+4, 0, 0x00, 0x00, 0x00, 0x40)},
		{"no authorization area", nvExtendResponse(tpmSTSessions, tpmHeaderSize+4, 0, 0x00, 0x00, 0x00, 0x00)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() { _, err = sendNVExtend(t, tt.rsp) })
			assert.ErrorIs(t, err, ErrMalformedNVExtendResponse)
		})
	}
}
