package tpm2

import (
	"github.com/google/go-tpm/tpm2/transport"
)

// openUnixSocket reports ErrDeviceTransportUnsupported: go-tpm's Unix domain
// socket transport is not built for Windows.
func openUnixSocket(string) (transport.TPMCloser, error) {
	return nil, ErrDeviceTransportUnsupported
}
