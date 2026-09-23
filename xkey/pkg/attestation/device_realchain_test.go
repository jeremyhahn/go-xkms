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

package attestation_test

import (
	"bufio"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// galaxyS23UltraChain is a genuine StrongBox attestation chain captured from a
// retail Samsung Galaxy S23 Ultra. It lives beside the emulator fixture in the
// root module's android package.
const galaxyS23UltraChain = "../../../pkg/attestation/android/testdata/android_sm_s918u_chain.txt"

// loadDERChain reads a captured chain fixture: base64 DER, leaf first, with
// '#' comment lines.
func loadDERChain(t *testing.T, path string) [][]byte {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	var chain [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(line)
		require.NoError(t, err)
		chain = append(chain, der)
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, chain)
	return chain
}

// loadProductionTrust builds the trust pool exactly as pairing does: an empty
// file trust store merged with the embedded Google hardware attestation roots.
func loadProductionTrust(t *testing.T) *attestation.Trust {
	t.Helper()

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	trust, err := attestation.LoadTrust(store)
	require.NoError(t, err)
	return trust
}

// TestRealHandsetAttestationSatisfiesTheHardwarePolicy runs genuine retail
// hardware evidence through every check of VerifyDeviceAttestation that a
// captured chain can speak to (go-xkms#132): the chain verifies to an embedded
// Google root at or above the TEE bar, the boot state is attested verified and
// locked, and the TEE-enforced list says the key was GENERATED there and may
// SIGN. The synthetic DAK fixtures encode those claims themselves; only a real
// handset shows the parser reads them from where Keymint actually puts them.
func TestRealHandsetAttestationSatisfiesTheHardwarePolicy(t *testing.T) {
	chain, err := attestation.ParseDERChain(loadDERChain(t, galaxyS23UltraChain))
	require.NoError(t, err)
	trust := loadProductionTrust(t)

	parsed, err := xkms.ParseAndroidKeyAttestation(chain[0])
	require.NoError(t, err)

	desc, err := xkms.VerifyAndroidKeyAttestation(chain, attestation.VerifyOptions(trust.Pool))
	require.NoError(t, err)
	assert.Equal(t, parsed, desc, "verification must report the same claims the parser reads")

	assert.Equal(t, xkms.AndroidSecurityLevelStrongBox, desc.AttestationSecurityLevel)
	assert.Equal(t, xkms.AndroidSecurityLevelStrongBox, desc.KeymasterSecurityLevel)

	// Samsung's StrongBox records its claims in the hardware-enforced list,
	// which the parser exposes as TeeEnforced regardless of which secure
	// element enforced them.
	tee := desc.TeeEnforced
	assert.Equal(t, xkms.AndroidOriginGenerated, tee.Origin, "TEE-enforced Origin (tag 702)")
	assert.Contains(t, tee.Purpose, xkms.AndroidPurposeSign, "TEE-enforced Purpose (tag 1)")
	require.NoError(t, attestation.RequireAttestedKeyOrigin(desc))

	rot, err := attestation.RequireAttestedBootState(desc)
	require.NoError(t, err)
	assert.True(t, rot.DeviceLocked)
	assert.Equal(t, xkms.AndroidVerifiedBootVerified, rot.VerifiedBootState)

	anchor, err := attestation.VerifiedTrustAnchor(chain, trust.Pool)
	require.NoError(t, err)
	assert.Equal(t, chain[len(chain)-1].Raw, anchor.Raw, "the chain must anchor at its own Google root")

	assert.Equal(t, "xkey-fixture-challenge", string(desc.AttestationChallenge))
}

// TestRealHandsetAttestationIsRefusedAsAPairingAnswer shows why the captured
// chain passes the policy above but not VerifyDeviceAttestation as a whole:
// the capture test generates its key under a fixed fixture challenge rather
// than a pairing genesis challenge, and no live signature accompanies it. A
// public chain replayed without the protocol's challenge must be refused.
func TestRealHandsetAttestationIsRefusedAsAPairingAnswer(t *testing.T) {
	result := &pairing.LocalAttestDeviceResult{
		ProtocolVersion:  pairing.AttestProtocolV2,
		CertificateChain: loadDERChain(t, galaxyS23UltraChain),
	}
	challenge, err := attestation.NewChallenge(pairing.AttestPurposePair, []byte("channel-binding"))
	require.NoError(t, err)

	_, err = attestation.VerifyDeviceAttestation(result, challenge, loadProductionTrust(t))
	require.Error(t, err)
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	require.ErrorIs(t, err, pairing.ErrAttestGenesisChallenge,
		"the chain itself passes policy; only the missing protocol challenge may refuse it")
}
