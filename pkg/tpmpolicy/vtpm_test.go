// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpmpolicy

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the real swtpm binary, a declared test dependency of
// `make test`. They never open the in-process simulator: it is a process-wide
// singleton, and a vTPM is by definition a second TPM. The "physical" TPM
// here is a swtpm of its own, started for the pseudo-tenant
// "system-physical" by a separate supervisor.

// physicalTenant names the swtpm standing in for the physical TPM.
const physicalTenant = "system-physical"

// fixedStateKey is the state key of the swtpm standing in for the physical
// TPM.
type fixedStateKey []byte

// StateKey returns the fixed key.
func (k fixedStateKey) StateKey(string) ([]byte, error) { return k, nil }

// shortDir returns a temporary directory with a short path: Unix socket
// paths are limited to about 108 bytes, which t.TempDir() can exceed.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tpmpolicy")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	return dir
}

// newSWTPMFixture starts a swtpm as the physical TPM, provisions it, and
// builds a Service over it whose vTPMs run under their own supervisor.
func newSWTPMFixture(t *testing.T) *fixture {
	t.Helper()
	manager, err := vtpm.NewManager(vtpm.Config{StateDir: t.TempDir(), RunDir: shortDir(t), Logger: quietLogger},
		fixedStateKey(bytes.Repeat([]byte{0x5a}, vtpm.StateKeySize)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	require.NoError(t, manager.Start(context.Background(), physicalTenant))
	socket, err := manager.Transport(physicalTenant)
	require.NoError(t, err)
	conn := socket
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	keys := store.NewFileBackend(quietLogger, storage.NewMemory())
	cfg := pkgtpm2.DefaultConfig
	cfg.UseSimulator = false
	tpm := provisionedTPM(t, &pkgtpm2.Params{Config: &cfg, Backend: keys, Logger: quietLogger, Transport: conn})
	return newFixture(t, tpm, keys, &vtpm.Config{StateDir: t.TempDir(), RunDir: shortDir(t), Logger: quietLogger})
}

// TestService_VTPMMode proves a vtpm tenant's objects live in a vTPM of its
// own that survives a stop and start -- and a service restart -- with the
// same state key, and that the key is sealed in the system scope under the
// vtpm-state policy.
func TestService_VTPMMode(t *testing.T) {
	f := newSWTPMFixture(t)

	require.NoError(t, f.svc.SetMode(f.ctx, "acme", ModeVTPM, nil))
	status := f.svc.VTPMStatus("acme")
	assert.True(t, status.Running)
	mode, err := f.svc.Mode(f.ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, ModeVTPM, mode)

	st := f.scopeTPM("acme")
	f.closeScopeTPM(st)
	assert.NotSame(t, f.tpm, st.TPM, "a vtpm tenant's objects are not on the physical TPM")

	statePolicy, err := f.svc.Policy(f.ctx, "", VTPMStatePolicy)
	require.NoError(t, err)
	assert.Equal(t, []uint{pkgtpm2.DefaultPlatformPCR}, statePolicy.PCRs)
	objects, err := f.svc.ObjectsOf(f.ctx, "", VTPMStatePolicy)
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/vtpm-state-acme"}, objects)

	f.createPolicy("acme", "boot")
	key := f.createKey("acme", "signer", "boot", nil)
	require.NoError(t, f.sign("acme", key))
	stateKey, err := f.svc.StateKey("acme")
	require.NoError(t, err)
	assert.Len(t, stateKey, vtpm.StateKeySize)

	require.NoError(t, f.svc.StopVTPM(f.ctx, "acme"))
	assert.False(t, f.svc.VTPMStatus("acme").Running)
	require.NoError(t, f.svc.StartVTPM(f.ctx, "acme"))
	assert.True(t, f.svc.VTPMStatus("acme").Running)
	require.NoError(t, f.svc.StartVTPM(f.ctx, "acme"), "starting a running vTPM is a no-op")
	require.NoError(t, f.sign("acme", key), "the key survives the vTPM restart")
	again, err := f.svc.StateKey("acme")
	require.NoError(t, err)
	assert.Equal(t, stateKey, again)

	// A new process has no cached state key: it unseals it from the system
	// scope, and the vTPM's saved state opens with it.
	f.restart()
	unsealed, err := f.svc.StateKey("acme")
	require.NoError(t, err)
	assert.Equal(t, stateKey, unsealed)
	require.NoError(t, f.sign("acme", key))

	// A vtpm tenant with objects cannot change mode; the vTPM keeps its
	// state key when an empty tenant leaves and returns to vtpm mode.
	var inUse *ScopeInUseError
	require.ErrorAs(t, f.svc.SetMode(f.ctx, "acme", ModeShared, nil), &inUse)
	require.NoError(t, f.svc.SetMode(f.ctx, "globex", ModeVTPM, nil))
	globexKey, err := f.svc.StateKey("globex")
	require.NoError(t, err)
	require.NoError(t, f.svc.SetMode(f.ctx, "globex", ModeShared, nil))
	assert.False(t, f.svc.VTPMStatus("globex").Running, "leaving vtpm mode stops the vTPM")
	require.NoError(t, f.svc.SetMode(f.ctx, "globex", ModeVTPM, nil))
	resumed, err := f.svc.StateKey("globex")
	require.NoError(t, err)
	assert.Equal(t, globexKey, resumed)
	f.createPolicy("globex", "boot")

	require.ErrorIs(t, f.svc.StopVTPM(f.ctx, "initech"), ErrNotVTPMMode)
	require.ErrorIs(t, f.svc.StartVTPM(f.ctx, "initech"), ErrNotVTPMMode)
}
