package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOpenUnixSocketTransport_Windows proves the socket transport reports
// ErrDeviceTransportUnsupported on Windows instead of failing to build.
func TestOpenUnixSocketTransport_Windows(t *testing.T) {
	transport, err := OpenUnixSocketTransport(`C:\swtpm\tpm.sock`)
	assert.ErrorIs(t, err, ErrDeviceTransportUnsupported)
	assert.Nil(t, transport)
}

// TestOpenDeviceTransport_SocketPath_Windows proves a ".sock" device path is
// still routed to the socket opener, and so reports the sentinel.
func TestOpenDeviceTransport_SocketPath_Windows(t *testing.T) {
	transport, err := OpenDeviceTransport(`C:\swtpm\tpm.sock`)
	assert.ErrorIs(t, err, ErrDeviceTransportUnsupported)
	assert.Nil(t, transport)
}
