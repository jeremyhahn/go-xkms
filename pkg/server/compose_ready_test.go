package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newServerForTest builds a server with New and shuts it down when the test
// ends. A server that is never shut down leaves its embedded qrdb node
// running for the rest of the package's tests, loading the process the
// timing-sensitive tests share.
func newServerForTest(t *testing.T, cfg *config.Config, opts ...Option) *Server {
	t.Helper()
	s, err := New(cfg, opts...)
	require.NoError(t, err)
	shutdownOnCleanup(t, s)
	return s
}

// shutdownOnCleanup shuts s down when the test ends.
func shutdownOnCleanup(t *testing.T, s *Server) {
	t.Helper()
	t.Cleanup(func() {
		assert.NoError(t, s.Shutdown())
	})
}

// TestNew_ComposesSSHClientBeforePublishingService proves New builds the SSH
// client before it publishes the XKMSService, so the first module RPC binds
// a ready service and does not create the "ssh" database within its own
// deadline (DS-4012).
func TestNew_ComposesSSHClientBeforePublishingService(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	// The SSH database needs a bound administrator, which first boot only
	// creates when a CA is configured.
	s := newUnixCATestServer(t)

	require.NotNil(t, s.XKMSService())
	require.NotNil(t, s.sshClient, "the SSH client must be composed by the time New returns")
	require.Same(t, s.sshClient, s.ensureSSHClient())
}

// TestComposeSSHClient_NilServiceDoesNotLatch proves a call made before the
// service is composed returns nil without consuming the sync.Once, so it
// cannot leave the server without an SSH client for its lifetime.
func TestComposeSSHClient_NilServiceDoesNotLatch(t *testing.T) {
	s := &Server{}

	require.Nil(t, s.composeSSHClient(nil))

	ran := false
	s.sshOnce.Do(func() { ran = true })
	require.True(t, ran, "a nil service must not consume the sync.Once")
}
