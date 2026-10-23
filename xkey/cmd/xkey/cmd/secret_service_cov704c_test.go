package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/secretservice"
)

// c704cBus stands in for the D-Bus session bus the daemon claims.
type c704cBus struct {
	startErr, stopErr error
	started, stopped  bool
}

func (b *c704cBus) Start() error {
	b.started = true
	return b.startErr
}

func (b *c704cBus) Stop() error {
	b.stopped = true
	return b.stopErr
}

// c704cSecretService initialises a barrier, puts the daemon on a fake bus
// and returns the bus and the command's run function.
func c704cSecretService(t *testing.T, password string) (*c704cBus, func() (string, error)) {
	t.Helper()
	isolateBarrier(t)
	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)
	t.Setenv("XKEY_BARRIER_PASSWORD", password)

	bus := &c704cBus{}
	saved := secretServiceOnBus
	secretServiceOnBus = func(*secretservice.Daemon) secretServiceBusHost { return bus }
	t.Cleanup(func() { secretServiceOnBus = saved })

	buf, run := newSecretServiceRun(t)
	return bus, func() (string, error) {
		err := run()
		return buf.String(), err
	}
}

// c704cServeUntilSIGTERM runs the daemon until a SIGTERM stops it.
func c704cServeUntilSIGTERM(t *testing.T, run func() (string, error)) (string, error) {
	t.Helper()
	var out string
	done := make(chan error, 1)
	go func() {
		var err error
		out, err = run()
		done <- err
	}()
	err := c704cStopWithSIGTERM(t, done)
	return out, err
}

func TestC704cSecretService_ServesUntilSIGTERM(t *testing.T) {
	for name, tt := range map[string]struct {
		password string
		sealed   string
	}{
		"unsealed by the startup password": {password: "correct-horse", sealed: "Sealed: false"},
		"sealed without one":               {password: "", sealed: "Sealed: true"},
	} {
		t.Run(name, func(t *testing.T) {
			bus, run := c704cSecretService(t, tt.password)

			out, err := c704cServeUntilSIGTERM(t, run)
			require.NoError(t, err)
			assert.True(t, bus.started)
			assert.True(t, bus.stopped, "the bus name is released on shutdown")
			assert.Contains(t, out, "Secret Service daemon started")
			assert.Contains(t, out, "Name:   "+secretservice.BusName)
			assert.Contains(t, out, tt.sealed)
			assert.Contains(t, out, "Shutting down Secret Service daemon...")
		})
	}
}

func TestC704cSecretService_BusFailures(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		bus, run := c704cSecretService(t, "")
		bus.startErr = errC704cHost

		out, err := run()
		require.ErrorIs(t, err, ErrSecretServiceStartFailed)
		require.ErrorIs(t, err, errC704cHost)
		assert.False(t, bus.stopped)
		assert.NotContains(t, out, "Secret Service daemon started")
	})
	t.Run("stop", func(t *testing.T) {
		bus, run := c704cSecretService(t, "")
		bus.stopErr = errC704cHost

		_, err := c704cServeUntilSIGTERM(t, run)
		require.ErrorIs(t, err, errC704cHost)
	})
}
