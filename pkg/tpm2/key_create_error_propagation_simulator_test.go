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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// newUnprovisionedSimHarness opens a fresh TPM simulator with the harness's
// baseline configuration but, unlike newSimHarness, returns before any
// provisioning primitive runs against it: every persistent handle the
// baseline config names (EK, SSRK, Platform SRK, IAK) is still empty.
//
// This is what CreateEK, CreateSRK and CreateIAK need to be swept by
// sweepEachCommandFailure in isolation: newSimHarness's auto-provisioning
// would already occupy their target handles, so a second call would fail
// immediately at EvictControl ("already persistent") rather than exercising
// the command sequence sweepEachCommandFailure's precondition subtest needs
// to complete once, cleanly, before it starts cutting the transport off one
// command earlier each time.
func newUnprovisionedSimHarness(t *testing.T, mutate func(*Config)) *simHarness {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	storageFactory, err := store.NewStorageFactory(logger, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageFactory.Close() })

	config := newSimConfig(t)
	if mutate != nil {
		mutate(config)
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: false,
		Config:       config,
		Backend:      storageFactory.KeyBackend(),
		Transport:    sim.Transport(),
		FQDN:         "node1.example.com",
	}

	tpmIface, err := NewTPM2(params)
	require.ErrorIs(t, err, ErrNotInitialized, "a fresh simulator must report unprovisioned")
	require.NotNil(t, tpmIface)

	tpmImpl, ok := tpmIface.(*TPM2)
	require.True(t, ok, "NewTPM2 must return *TPM2")

	t.Cleanup(func() { _ = tpmIface.Close() })

	return &simHarness{
		TPM:     tpmImpl,
		Backend: storageFactory.KeyBackend(),
		Logger:  logger,
	}
}

// TestCreateEK_EveryCommandFailurePropagates sweeps CreateEK's command
// sequence (TPM2_CreatePrimary under the Endorsement hierarchy, then
// TPM2_EvictControl to persist it) proving a failure at either round trip
// surfaces as an error instead of leaving ekAttrs reporting a key that was
// never actually persisted.
func TestCreateEK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, nil)
		ekAttrs, err := EKAttributesFromConfig(*h.TPM.config.EK, nil, h.TPM.config.IDevID)
		require.NoError(t, err)
		// The Endorsement hierarchy auth is still empty on a freshly opened
		// simulator: no SetHierarchyAuth has run. ProvisionOwner overwrites
		// the config-derived HierarchyAuth with the caller's soPIN (nil, for
		// Provision(nil)) for exactly this reason; mirrored here so
		// CreateEK's PasswordAuth matches the hierarchy's live auth instead
		// of failing every call with TPM_RC_BAD_AUTH.
		ekAttrs.TPMAttributes.HierarchyAuth = nil

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.CreateEK(ekAttrs)
		}
	},
		// No EK is resident yet, so CreateEK's hierarchy session is salted
		// against an ephemeral NULL-hierarchy key: TPM2_ReadPublic of the
		// absent EK handle (1), TPM2_CreatePrimary of the salt key (2),
		// TPM2_StartAuthSession (3) and the salt key's flush (4). Then
		// TPM2_CreatePrimary (5), the session's flush (6) and
		// TPM2_EvictControl (7). CreateEK reads its own new public area back
		// through tpm.ParsePublicKey (tpm.go), which issues
		// TPM2_LoadExternal (8, required: its failure aborts ParsePublicKey
		// and CreateEK with it), TPM2_ReadPublic (9, likewise required),
		// then flushes the externally-loaded object it created (10) in its
		// own deferred, best-effort tpm.Flush. CreateEK's own trailing
		// tpm.Flush of the EK's transient handle (11) is deferred the same
		// way and is the last command of all. Both flushes log their failure
		// rather than return it, matching tpm.Flush's contract everywhere
		// else.
		10, 11)
}

// TestCreateSRK_EveryCommandFailurePropagates sweeps CreateSRK's command
// sequence (TPM2_CreatePrimary under the Owner hierarchy, then
// TPM2_EvictControl to persist it) the same way
// TestCreateEK_EveryCommandFailurePropagates does for the EK.
func TestCreateSRK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, nil)
		srkAttrs, err := SRKAttributesFromConfig(*h.TPM.config.SSRK)
		require.NoError(t, err)
		// See the matching comment in TestCreateEK_EveryCommandFailurePropagates:
		// the Owner hierarchy auth is still empty until SetHierarchyAuth runs.
		srkAttrs.TPMAttributes.HierarchyAuth = nil

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.CreateSRK(srkAttrs)
		}
	},
		// The last command is the tpm.Flush deferred inside CreateSRK's own
		// trailing tpm.ParsePublicKey readback (tpm.go), for the object
		// TPM2_LoadExternal placed there; like every other tpm.Flush call,
		// its failure is logged rather than returned.
		11)
}

// TestCreateIAK_EveryCommandFailurePropagates sweeps CreateIAK's command
// sequence (TPM2_CreatePrimary under the Endorsement hierarchy,
// TPM2_EvictControl to persist it, then TPM2_CertifyCreation over the new
// key) proving a failure at any of the three round trips surfaces as an
// error rather than caching a half-built IAK as this TPM's identity.
//
// CreateIAK authorizes both the primary's creation and its own
// certification with password auth taken from ekAttrs.TPMAttributes and the
// configured IAK auth; it never loads or salts a session off an actual EK
// object, so ekAttrs built straight from EKAttributesFromConfig exercises
// it exactly as ProvisionOwner does, without an EK ever having been created
// on this simulator.
func TestCreateIAK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newUnprovisionedSimHarness(t, nil)
		ekAttrs, err := EKAttributesFromConfig(*h.TPM.config.EK, nil, h.TPM.config.IDevID)
		require.NoError(t, err)
		// See the matching comment in TestCreateEK_EveryCommandFailurePropagates:
		// the Endorsement hierarchy auth is still empty until SetHierarchyAuth
		// runs, and CreateIAK authorizes TPM2_CreatePrimary with it.
		ekAttrs.TPMAttributes.HierarchyAuth = nil

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.CreateIAK(ekAttrs, nil)
			return err
		}
	},
		// The last command is CreateIAK's deferred best-effort flush of the
		// primary's transient handle: the defer is registered right after
		// TPM2_CreatePrimary succeeds, so it fires on every return path from
		// that point on, but a defer always runs last, after
		// TPM2_EvictControl and TPM2_CertifyCreation have already sent.
		9)
}

// TestCreateIDevID_EveryCommandFailurePropagates sweeps CreateIDevID's
// command sequence -- primary creation, the probe/evict of any prior key at
// its handle, persisting it, certifying it under the IAK through a DevID
// admin policy session, and reading the IAK back to learn its signing
// scheme -- proving a failure anywhere in that chain surfaces as an error
// rather than this TPM caching a device identity whose certification never
// actually completed.
//
// Unlike CreateEK/CreateSRK/CreateIAK, CreateIDevID genuinely needs a live
// IAK: TPM2_Certify's SignHandle addresses the IAK's real persistent handle,
// which only exists once Provision has run. The setup below is
// newIdentityHarness's own provisioning half (idevid_csr_simulator_test.go),
// stopping short of the CreateIDevID call that function makes so the sweep
// can drive it one transport failure at a time instead.
func TestCreateIDevID_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, func(c *Config) {
			c.IDevID = &IDevIDConfig{
				CN:                 "device-id-001",
				Debug:              true,
				Hash:               crypto.SHA256.String(),
				Handle:             0x81020000,
				KeyAlgorithm:       x509.RSA.String(),
				Manufacturer:       "ATT",
				Model:              "xkms-test-device",
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
				Serial:             "SN-0000-0001",
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			}
		})

		iakAttrs, err := h.TPM.IAKAttributes()
		require.NoError(t, err, "provisioning must leave a usable IAK behind")
		ekPub, err := h.TPM.EKRSA()
		require.NoError(t, err, "the provisioned EK must be readable")
		ekCert := selfSignedCertForKey(t, ekPub)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, _, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
			return err
		}
	},
		// The last command is CreateIDevID's own deferred best-effort flush
		// of the primary's transient handle, registered right after
		// TPM2_CreatePrimary succeeds; like every other tpm.Flush call in
		// this package it logs a failure instead of returning it, and a
		// defer always runs after every other command the function issues.
		33)
}
