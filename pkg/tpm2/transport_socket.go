//go:build !windows

package tpm2

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// openUnixSocket opens a TPM command channel over a Unix domain socket
// (e.g. swtpm). It is the single place the socket transport is opened.
func openUnixSocket(socketPath string) (transport.TPMCloser, error) {
	return linuxudstpm.Open(socketPath)
}
