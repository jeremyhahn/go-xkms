// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// These tests are the GUI half of the pairing-time attestation contract
// (#115, #131). Until now PhoneService.Pair ran the handshake, sent the
// pairing confirmation and wrote the record, and never asked the phone for
// an attestation at all — so a device that could never produce a valid one
// paired from the desktop GUI without anything noticing, while `xkey device
// pair` refused it by default.
//
// Every test here drives the REAL pairing path from the handshake on, against
// the same in-memory phone the CLI's interop gate uses: a real Noise XX
// responder holding a persistent attested key. What they assert on is what
// gets SAVED to devices.yaml, because the record is what every later
// connection is judged against; a test that only looked at the return value
// could not tell a refusal from a pairing that wrote a claim it never checked.

// pairingHarness is one isolated desktop: its own home from isolateHome (so
// devices.yaml, xkey.yaml and the trust store land in a temp dir), and a
// PhoneService wired to a trust store the test controls.
type pairingHarness struct {
	t      *testing.T
	home   string
	svc    *PhoneService
	store  truststore.TrustStore
	events []events.Event

	// lastLocalPrivate is a copy of the raw Noise private scalar the most
	// recent pair() call generated, captured before pairOverTransport seals
	// and persists it. A #42 test uses it to assert that value never appears
	// verbatim in what actually gets written to disk.
	lastLocalPrivate []byte
}

func newPairingHarness(t *testing.T) *pairingHarness {
	t.Helper()

	home := isolateHome(t)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: filepath.Join(home, "trust")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	h := &pairingHarness{t: t, home: home, store: store}
	h.svc = &PhoneService{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h.svc.connState.deviceName.Store("")
	h.svc.SetTrustStore(store)
	h.svc.SetBarrierService(newUnsealedTestBarrierService(t))
	h.svc.SetEventEmitter(func(evt events.Event) { h.events = append(h.events, evt) })
	return h
}

// trust installs ca as an Android hardware attestation anchor on this desktop.
func (h *pairingHarness) trust(ca *attesttest.CA) {
	h.t.Helper()
	require.NoError(h.t, h.store.AddCertificateWithOptions(ca.Cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeAndroidHardware,
		Source:  "test",
	}))
}

// writeDevicesConfig seeds devices.yaml before pairing, so a test can state
// the user plane of the pairing policy the way `xkey device pair` reads it.
func (h *pairingHarness) writeDevicesConfig(body string) {
	h.t.Helper()
	dir := filepath.Join(h.home, ".xkey")
	require.NoError(h.t, os.MkdirAll(dir, 0o700))
	require.NoError(h.t, os.WriteFile(filepath.Join(dir, devicesConfigFileName), []byte(body), 0o600))
}

// fixtureAllowListYAML is the attestation_policy keys that allow-list the
// attesttest fixture application, indented to sit inside that block.
var fixtureAllowListYAML = "  allowed_applications:\n" +
	"    - package_name: " + attesttest.AppPackage + "\n" +
	"      signing_digests:\n" +
	"        - " + hex.EncodeToString(attesttest.AppSigningDigest()) + "\n"

// allowFixtureApplication writes a devices.yaml whose attestation_policy
// allow-lists the fixture application and states nothing else (#1305).
func (h *pairingHarness) allowFixtureApplication() {
	h.t.Helper()
	h.writeDevicesConfig("attestation_policy:\n" + fixtureAllowListYAML)
}

// writeUnifiedConfig seeds xkey.yaml, the enterprise plane, where pkg/config
// resolves it for this test.
func (h *pairingHarness) writeUnifiedConfig(body string) {
	h.t.Helper()
	require.NoError(h.t, os.WriteFile(config.ConfigPath(), []byte(body), 0o600))
}

// savedConfig reads devices.yaml back the way the service does. ok is false
// when nothing was ever written.
func (h *pairingHarness) savedConfig() (cfg *phoneConfig, ok bool) {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.home, ".xkey", devicesConfigFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	require.NoError(h.t, err)
	cfg = &phoneConfig{}
	require.NoError(h.t, yaml.Unmarshal(data, cfg))
	return cfg, true
}

// savedDevice is the one record a successful pairing must have written.
func (h *pairingHarness) savedDevice(address string) *phoneConfigDevice {
	h.t.Helper()
	cfg, ok := h.savedConfig()
	require.True(h.t, ok, "a completed pairing must write devices.yaml")
	for i := range cfg.Devices {
		if cfg.Devices[i].Address == address {
			return &cfg.Devices[i]
		}
	}
	require.Failf(h.t, "record missing", "no device with address %s in devices.yaml", address)
	return nil
}

// pair drives pairOverTransport against device over an in-memory link, with
// the phone serving exchanges encrypted round trips. It returns whatever the
// service returned; the phone's own verdict is checked too, so a desktop that
// sends the phone something a real handset would refuse fails here rather
// than passing on a lenient stub.
func (h *pairingHarness) pair(device *attesttest.Phone, exchanges int, address string) (*PairedDevice, error) {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initiator, responder := attesttest.NewMemTransportPair()
	done := make(chan error, 1)
	device.Serve(ctx, h.t, responder, false, exchanges, done)

	localKey, err := pairing.GenerateStaticKey()
	require.NoError(h.t, err)
	defer localKey.Destroy()
	h.lastLocalPrivate = append([]byte(nil), localKey.Private...)

	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: localKey,
		IsInitiator:    true,
	})
	require.NoError(h.t, err)

	paired, pairErr := h.svc.pairOverTransport(ctx, initiator, session, localKey, address)

	// The phone must have been satisfied with every exchange it served. A
	// desktop that stops early leaves the phone waiting; cancel so it reports
	// instead of outliving the test.
	cancel()
	select {
	case phoneErr := <-done:
		if !errors.Is(phoneErr, context.Canceled) {
			require.NoError(h.t, phoneErr, "the phone refused something the desktop sent")
		}
	case <-time.After(5 * time.Second):
		h.t.Fatal("phone responder did not stop")
	}
	return paired, pairErr
}

// attestationEvents is what the frontend was told about the attestation.
func (h *pairingHarness) attestationEvents() []events.AttestationResultPayload {
	h.t.Helper()
	var out []events.AttestationResultPayload
	for _, evt := range h.events {
		if payload, ok := evt.Payload.(events.AttestationResultPayload); ok {
			out = append(out, payload)
		}
	}
	return out
}

func healthyDAK(t *testing.T, ca *attesttest.CA) *attesttest.DAK {
	t.Helper()
	return attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
}

const testPairAddress = "AA:BB:CC:DD:EE:FF"

// TestPairRefusesAnUnattestableDeviceByDefault is the gate itself.
//
// The phone answers the attestation, but its chain leads to a root this
// desktop does not trust. With no policy stated anywhere, the pairing must be
// refused and NOTHING written: not a record without claims, not a record with
// them — no devices.yaml at all.
func TestPairRefusesAnUnattestableDeviceByDefault(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")

	paired, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	require.Nil(t, paired)

	_, written := h.savedConfig()
	require.False(t, written, "a refused pairing must not write devices.yaml")

	evts := h.attestationEvents()
	require.Len(t, evts, 1, "the frontend is told why the pairing failed")
	require.False(t, evts[0].Success)
}

// TestPairRefusesWhenNoApplicationIsAllowListed is #1305's fail-closed case on
// the GUI surface: a trusted, healthy device is still refused while
// devices.yaml allow-lists no application, and the refusal names the missing
// configuration rather than blaming the device.
func TestPairRefusesWhenNoApplicationIsAllowListed(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, ca)), 1, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	require.ErrorIs(t, err, pairing.ErrApplicationPolicyUnconfigured)
	_, written := h.savedConfig()
	require.False(t, written)
}

// TestPairRefusesAnotherApplication is #1305 itself on the GUI surface: a
// genuine, trusted handset whose attested key was generated by an application
// off the allow-list is refused.
func TestPairRefusesAnotherApplication(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()

	claims := attesttest.DeviceKeyClaims()
	claims.RootOfTrust = attesttest.AttestedBootState()
	claims.ApplicationID.Packages[0].Name = "com.example.malicious"
	dak := attesttest.NewDAKWithClaims(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, claims)

	_, err := h.pair(attesttest.NewPhone(t, dak), 2, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	require.ErrorIs(t, err, pairing.ErrApplicationDenied)
	cfg, _ := h.savedConfig()
	require.Empty(t, cfg.Devices, "a refused pairing must not write a device record")
}

// TestPairRefusesAMalformedAttestationByDefault covers a device that answers
// with a chain the desktop trusts but a signature that proves nothing: the
// relay case. The chain is genuine; the key that signed the challenge is not
// the one the chain certifies.
func TestPairRefusesAMalformedAttestationByDefault(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)

	device := attesttest.NewPhone(t, healthyDAK(t, ca))
	device.Mutate = func(r *pairing.LocalAttestDeviceResult) { r.Signature[0] ^= 0xff }

	_, err := h.pair(device, 2, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	_, written := h.savedConfig()
	require.False(t, written)
}

// TestPairRefusesWithoutATrustStoreByDefault is the fail-closed case for
// missing authorization material. With nothing to judge evidence against the
// service must not even ask for it, and must refuse rather than pair unchecked.
//
// The phone serves ONE exchange, the pairing confirmation: a desktop that
// went on to request an attestation it could not judge would leave the phone
// reporting an unexpected second round trip.
func TestPairRefusesWithoutATrustStoreByDefault(t *testing.T) {
	h := newPairingHarness(t)
	h.svc.SetTrustStore(nil)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, ca)), 1, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	require.ErrorIs(t, err, ErrPhoneAttestFailed)
	_, written := h.savedConfig()
	require.False(t, written)
}

// TestPairRecordsAVerifiedAttestation is the positive half: a contract-faithful
// device pairs, and the record carries exactly what the CLI's pairing would
// have written for it (#131) — the device fingerprint the phone derived
// independently from its own key, the protocol version, the security level,
// the boot state and the attestation time.
func TestPairRecordsAVerifiedAttestation(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()
	dak := healthyDAK(t, ca)
	device := attesttest.NewPhone(t, dak)
	device.Name = "Pixel 9"

	before := time.Now().UTC().Add(-time.Second)
	paired, err := h.pair(device, 2, testPairAddress)
	require.NoError(t, err, "a contract-faithful device must pair from the GUI")
	require.Equal(t, "Pixel 9", paired.Name)
	require.Equal(t, testPairAddress, paired.Address)

	rec := h.savedDevice(testPairAddress)
	require.Equal(t, hex.EncodeToString(dak.Fingerprint()), rec.DeviceFingerprint,
		"the stored fingerprint must equal the phone's own SPKI hash — the identity the reconnect check binds to")
	require.Equal(t, pairing.AttestProtocolV2, rec.AttestationProtocolVersion,
		"a GUI pairing must establish the same challenge-response binding the CLI does")
	require.Equal(t, "strongbox", rec.SecurityLevel)
	require.True(t, rec.BootStateVerified)
	require.NotEmpty(t, rec.DeviceBootHashHex)
	require.False(t, rec.LastDeviceAttestationTime.Before(before))
	require.Equal(t, rec.LastDeviceAttestationTime, paired.LastSeen)

	// The pairing half is intact too.
	require.NotEmpty(t, rec.NoisePublicKey)
	require.NotEmpty(t, rec.LocalNoisePrivateKey)
	require.False(t, rec.PairedAt.IsZero())

	// And the record is one the reconnect path will DEMAND a proof for.
	require.NoError(t, xkeyAttestation.DeviceBindingFor(*rec).Validate())

	evts := h.attestationEvents()
	require.Len(t, evts, 1)
	require.True(t, evts[0].Success)
}

// TestPairSealsTheLocalNoisePrivateKeyAndNeverWritesItAsPlaintext is the #42
// gate on the GUI pairing path. It asserts two distinct things: the persisted
// field carries the sealed marker, and -- because a bug could seal one copy
// while some other code path still wrote the raw value -- the actual bytes
// devices.yaml was written with never contain the plaintext base64 of the
// private scalar this pairing generated.
func TestPairSealsTheLocalNoisePrivateKeyAndNeverWritesItAsPlaintext(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()
	device := attesttest.NewPhone(t, healthyDAK(t, ca))
	device.Name = "Pixel 9"

	_, err := h.pair(device, 2, testPairAddress)
	require.NoError(t, err)
	require.NotEmpty(t, h.lastLocalPrivate)
	plaintextBase64 := base64.StdEncoding.EncodeToString(h.lastLocalPrivate)

	rec := h.savedDevice(testPairAddress)
	require.True(t, pairing.IsSealedNoiseKey(rec.LocalNoisePrivateKey),
		"the persisted field must carry the #42 sealed marker, not legacy plaintext base64")
	require.NotEqual(t, plaintextBase64, rec.LocalNoisePrivateKey)

	raw, err := os.ReadFile(filepath.Join(h.home, ".xkey", devicesConfigFileName))
	require.NoError(t, err)
	require.NotContains(t, string(raw), plaintextBase64,
		"the raw private scalar's base64 must never appear anywhere in devices.yaml")
}

// TestPairProceedsWithoutABarrierConfigured is the #42 owner ruling: a host
// with no barrier wired at all -- one was never initialized -- is not
// refused. Pairing completes exactly as xkey always did before #42: the key
// lands in the legacy plaintext base64 form, and the only difference is one
// warning logged, pointing at `xkey barrier init`.
func TestPairProceedsWithoutABarrierConfigured(t *testing.T) {
	h := newPairingHarness(t)
	h.svc.SetBarrierService(nil)
	var logBuf bytes.Buffer
	h.svc.log = slog.New(slog.NewTextHandler(&logBuf, nil))

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()
	device := attesttest.NewPhone(t, healthyDAK(t, ca))

	paired, err := h.pair(device, 2, testPairAddress)
	require.NoError(t, err, "no barrier configured must never refuse a pairing")
	require.NotNil(t, paired)

	rec := h.savedDevice(testPairAddress)
	require.False(t, pairing.IsSealedNoiseKey(rec.LocalNoisePrivateKey),
		"with no barrier configured the key must be written in the legacy plaintext form")
	require.NotEmpty(t, rec.LocalNoisePrivateKey)
	_, decodeErr := base64.StdEncoding.DecodeString(rec.LocalNoisePrivateKey)
	require.NoError(t, decodeErr, "the legacy form is plain base64 of the raw private scalar")

	require.Contains(t, logBuf.String(), "pairing key stored unencrypted",
		"exactly one warning must be logged for the operation")
	require.Contains(t, logBuf.String(), "xkey barrier init",
		"the warning must point the operator at the fix")
}

// TestPairRefusesWhenBarrierExistsButIsSealed is the other half of the #42
// owner ruling: once a barrier HAS been initialized on this host, it staying
// sealed (locked, or the app not yet unlocked) is not consent to fall back
// to plaintext -- pairing refuses.
func TestPairRefusesWhenBarrierExistsButIsSealed(t *testing.T) {
	h := newPairingHarness(t)
	barrierSvc := newUnsealedTestBarrierService(t)
	require.NoError(t, barrierSvc.Seal())
	h.svc.SetBarrierService(barrierSvc)

	_, err := h.svc.Pair(testPairAddress)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrPhoneBarrierRequired)
	_, ok := h.savedConfig()
	require.False(t, ok, "a pairing refused because the barrier is sealed must write nothing")
}

// TestPairAllowsAnUnattestableDeviceWhenPolicySaysSoAndRecordsNoClaim is the
// opt-in, and the invariant the opt-in is NOT allowed to move.
//
// The ruling made refusing configurable. It did not make recording
// configurable: when pairing proceeds without a verified attestation, the
// record must carry NOTHING about the device's hardware — not zeroed versions
// of the fields, absent ones — so the device reads as never attested, because
// it has not been.
func TestPairAllowsAnUnattestableDeviceWhenPolicySaysSoAndRecordsNoClaim(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")
	h.writeDevicesConfig("attestation_policy:\n  allow_unattestable_devices: true\n")

	paired, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)
	require.NoError(t, err, "policy allows it, so the pairing completes")
	require.True(t, paired.LastSeen.IsZero())

	rec := h.savedDevice(testPairAddress)
	require.NotEmpty(t, rec.NoisePublicKey, "the pairing half of the record is still written")
	require.NotEmpty(t, rec.LocalNoisePrivateKey)

	require.Empty(t, rec.SecurityLevel, "an unverified pairing must not claim a hardware security level")
	require.Empty(t, rec.DeviceFingerprint, "and must not claim a device identity — this is the #95 defect itself")
	require.Empty(t, rec.DeviceBootHashHex)
	require.False(t, rec.BootStateVerified)
	require.Zero(t, rec.AttestationProtocolVersion,
		"a record with no attested key must not demand a liveness proof it could never receive")
	require.True(t, rec.LastDeviceAttestationTime.IsZero(),
		"a device that was never attested has no last-attestation time")

	evts := h.attestationEvents()
	require.Len(t, evts, 1, "the frontend is told the pairing carries no verified identity")
	require.False(t, evts[0].Success)
}

// TestPairRefusesWhenTheEnterprisePlaneLocksItClosed is the case the lock
// exists for: the user's devices.yaml says allow, the sealed policy section
// says locked-and-refuse, and the sealed section wins. The same resolution the
// CLI uses, through the same function.
func TestPairRefusesWhenTheEnterprisePlaneLocksItClosed(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")
	h.writeDevicesConfig("attestation_policy:\n  allow_unattestable_devices: true\n")
	h.writeUnifiedConfig("policy:\n  lock_pairing_attestation_policy: true\n  pairing_allow_unattestable_devices: false\n")

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	cfg, written := h.savedConfig()
	require.True(t, written, "the seeded file is still there")
	require.Empty(t, cfg.Devices, "and nothing was added to it")
}

// TestPairRefusesWhenTheUnifiedConfigCannotBeRead pins the answer to a policy
// file that exists but cannot be parsed: it might be one that locks the
// setting closed, so the only answer that cannot be wrong in the direction an
// attacker wants is to refuse, even though the user plane says allow.
func TestPairRefusesWhenTheUnifiedConfigCannotBeRead(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")
	h.writeDevicesConfig("attestation_policy:\n  allow_unattestable_devices: true\n")
	h.writeUnifiedConfig("policy: [this is not a mapping\n")

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
}

// TestPairRefusesWhenTheEnterprisePlaneIsSealedAndUnverified is the #118
// contract on the GUI surface: the config directory is sealed, the sealed
// policy even locks the setting OPEN, and the user's devices.yaml says allow;
// but a GUI pairing has no SO PIN to verify the section with, so the section
// is not consulted and the pairing is refused. Locking the setting open is
// proved through `xkey device pair` with the SO PIN, never assumed here.
func TestPairRefusesWhenTheEnterprisePlaneIsSealedAndUnverified(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")
	h.writeDevicesConfig("attestation_policy:\n  allow_unattestable_devices: true\n")
	h.writeUnifiedConfig("policy:\n  lock_pairing_attestation_policy: true\n  pairing_allow_unattestable_devices: true\n")
	sealed := &config.PolicySection{LockPairingAttestationPolicy: true, PairingAllowUnattestableDevices: true}
	require.NoError(t, config.WritePolicyHMAC(sealed, "123456", config.PolicyHMACPath(config.ConfigDir())))

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)

	require.ErrorIs(t, err, ErrPhonePairAttestationRefused)
	cfg, written := h.savedConfig()
	require.True(t, written, "the seeded file is still there")
	require.Empty(t, cfg.Devices, "and nothing was added to it")
}

// TestPairHonoursAPersonalModePolicyLockedOpen is the other direction #118
// unblocks: with no HMAC file the policy section is the user's own file, no
// different in authority from devices.yaml, so a lock in the permissive
// direction is honoured over a devices.yaml that refuses. The record then
// carries no verified identity and the frontend is told so.
func TestPairHonoursAPersonalModePolicyLockedOpen(t *testing.T) {
	h := newPairingHarness(t)
	h.trust(attesttest.NewCA(t, "The Root This Desktop Trusts"))
	rogue := attesttest.NewCA(t, "A Root It Does Not")
	h.writeDevicesConfig("attestation_policy:\n  allow_unattestable_devices: false\n")
	h.writeUnifiedConfig("policy:\n  lock_pairing_attestation_policy: true\n  pairing_allow_unattestable_devices: true\n")

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, rogue)), 2, testPairAddress)
	require.NoError(t, err)

	cfg, _ := h.savedConfig()
	require.Len(t, cfg.Devices, 1)
	require.Empty(t, cfg.Devices[0].DeviceFingerprint, "no unverified claim is written down")
	evts := h.attestationEvents()
	require.Len(t, evts, 1)
	require.False(t, evts[0].Success, "the frontend is told the pairing carries no verified identity")
}

// TestPairPreservesTheUsersAttestationPolicyBlock covers the mirror. The GUI
// writes devices.yaml back as a whole, and before this change its mirror had
// no `attestation_policy` field at all, so every GUI save silently erased the
// user's `xkey device pair` settings. Keys this service does not consult must
// survive a save unchanged.
func TestPairPreservesTheUsersAttestationPolicyBlock(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.writeDevicesConfig(`attestation_policy:
  default_grace_period: 5m
  require_device_attestation: true
  min_security_level: strongbox
  allow_unattestable_devices: false
` + fixtureAllowListYAML)

	_, err := h.pair(attesttest.NewPhone(t, healthyDAK(t, ca)), 2, testPairAddress)
	require.NoError(t, err)

	cfg, _ := h.savedConfig()
	require.NotNil(t, cfg.AttestationPolicy, "the block must survive the save")
	require.False(t, cfg.AttestationPolicy.AllowUnattestableDevices)
	require.Equal(t, "5m", cfg.AttestationPolicy.Rest["default_grace_period"])
	require.Equal(t, true, cfg.AttestationPolicy.Rest["require_device_attestation"])
	require.Equal(t, "strongbox", cfg.AttestationPolicy.Rest["min_security_level"])
	require.Equal(t, attesttest.Applications(), cfg.AttestationPolicy.ApplicationPolicy,
		"the attested-application allow-list must survive the save (#1305)")
	require.NotContains(t, cfg.AttestationPolicy.Rest, "allowed_applications",
		"the allow-list is decoded into its typed field, not carried as an opaque key")
}

// TestRecordVerifiedAttestationNeverLowersTheProtocolVersion pins the
// anti-downgrade term of the record projection: a later result at a lower
// version must not walk a record back to the weaker model.
func TestRecordVerifiedAttestationNeverLowersTheProtocolVersion(t *testing.T) {
	rec := &phoneConfigDevice{AttestationProtocolVersion: pairing.AttestProtocolV2, DeviceFingerprint: "old"}

	xkeyAttestation.ApplyVerifiedAttestation(rec, &xkeyAttestation.Result{
		ProtocolVersion:   pairing.AttestProtocolV1,
		DeviceFingerprint: "new",
		SecurityLevel:     "tee",
	})

	require.Equal(t, pairing.AttestProtocolV2, rec.AttestationProtocolVersion,
		"the version is the anti-downgrade term; a term an attacker could lower is not one")
	require.Equal(t, "new", rec.DeviceFingerprint, "every other verified field is applied")
	require.Equal(t, "tee", rec.SecurityLevel)
}

// TestRecordVerifiedAttestationRaisesALegacyRecord is the other direction: a
// verified version 2 result upgrades a record that predates #129.
func TestRecordVerifiedAttestationRaisesALegacyRecord(t *testing.T) {
	when := time.Now().UTC().Truncate(time.Second)
	rec := &phoneConfigDevice{}

	xkeyAttestation.ApplyVerifiedAttestation(rec, &xkeyAttestation.Result{
		AttestationTime:   when,
		ProtocolVersion:   pairing.AttestProtocolV2,
		DeviceFingerprint: "fp",
		SecurityLevel:     "strongbox",
		BootStateVerified: true,
		BootHashHex:       "deadbeef",
	})

	require.Equal(t, pairing.AttestProtocolV2, rec.AttestationProtocolVersion)
	require.Equal(t, when, rec.LastDeviceAttestationTime)
	require.Equal(t, "fp", rec.DeviceFingerprint)
	require.Equal(t, "strongbox", rec.SecurityLevel)
	require.True(t, rec.BootStateVerified)
	require.Equal(t, "deadbeef", rec.DeviceBootHashHex)
}

// TestPhoneConfigAllowsUnattestablePairingReadsOnlyAnExplicitYes pins the user
// plane's zero value: nil config, absent block and an explicit false all read
// as "refuse".
func TestPhoneConfigAllowsUnattestablePairingReadsOnlyAnExplicitYes(t *testing.T) {
	var nilCfg *phoneConfig
	require.False(t, nilCfg.allowsUnattestablePairing())
	require.False(t, (&phoneConfig{}).allowsUnattestablePairing())
	require.False(t, (&phoneConfig{AttestationPolicy: &devicesAttestationPolicy{}}).allowsUnattestablePairing())
	require.True(t, (&phoneConfig{AttestationPolicy: &devicesAttestationPolicy{AllowUnattestableDevices: true}}).allowsUnattestablePairing())
}

// ---------------------------------------------------------------------------
// attestOverTransport: the manual "Attest Device" RPC (AttestDevice ->
// performAttestation -> attestOverTransport), driven end to end against the
// same in-memory phone fake the pairing tests use.
//
// Before this, AttestDevice sent local.attestKey -- an older, weaker method
// with no channel binding and no live signature -- while pairing and
// reconnect both already judged a device through
// xkeyAttestation.VerifyDeviceAttestation over local.attestDevice. These
// tests prove AttestDevice now goes through the same decision, so a device
// pairing accepts is a device the "Attest Device" button accepts too.
// ---------------------------------------------------------------------------

// attestReadyHarness pairs device over an in-memory link and returns the
// still-open transport and session, plus the record attestOverTransport
// needs, so a test can drive one more exchange on the SAME connection
// exactly as a user clicking "Attest Device" after connecting would.
func (h *pairingHarness) attestReadyHarness(device *attesttest.Phone, extraExchanges int, address string) (
	transport pairing.Transport, session *pairing.NoiseSession, cfgDevice *phoneConfigDevice, done <-chan error, cancel context.CancelFunc,
) {
	h.t.Helper()

	ctx, cancelFn := context.WithTimeout(context.Background(), 30*time.Second)

	initiator, responder := attesttest.NewMemTransportPair()
	doneCh := make(chan error, 1)
	// Pairing itself uses 2 exchanges (pairing.confirm, then the
	// attestForPairing local.attestDevice); extraExchanges are additional
	// manual attestations the test will drive afterward.
	device.Serve(ctx, h.t, responder, false, 2+extraExchanges, doneCh)

	localKey, err := pairing.GenerateStaticKey()
	require.NoError(h.t, err)
	h.t.Cleanup(localKey.Destroy)

	pairSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: localKey,
		IsInitiator:    true,
	})
	require.NoError(h.t, err)

	paired, err := h.svc.pairOverTransport(ctx, initiator, pairSession, localKey, address)
	require.NoError(h.t, err, "the harness device must pair cleanly before the attestation test runs")

	return initiator, pairSession, &phoneConfigDevice{Name: paired.Name, Address: paired.Address}, doneCh, cancelFn
}

// TestAttestOverTransport_Success proves the manual attestation path accepts
// a contract-faithful device and populates the display-rich AttestationResult
// the frontend depends on, entirely from the canonical local.attestDevice
// exchange and decision.
func TestAttestOverTransport_Success(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()
	dak := healthyDAK(t, ca)
	device := attesttest.NewPhone(t, dak)
	device.Name = "Pixel 9"

	transport, session, cfgDevice, done, cancel := h.attestReadyHarness(device, 1, testPairAddress)
	defer cancel()

	ctx, exchangeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer exchangeCancel()

	result, err := h.svc.attestOverTransport(ctx, transport, session, cfgDevice)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Verified, "attestation error: %s", result.ErrorMessage)
	require.Equal(t, "Pixel 9", result.DeviceName)
	require.Equal(t, "strongbox", result.SecurityLevel)
	require.Greater(t, result.ChainLength, 0)
	require.NotEmpty(t, result.Certificates)
	require.True(t, result.DeviceLocked)
	require.NotEmpty(t, result.BootHash)

	cancel()
	select {
	case phoneErr := <-done:
		if !errors.Is(phoneErr, context.Canceled) {
			require.NoError(t, phoneErr, "the phone refused something the desktop sent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("phone responder did not stop")
	}
}

// TestAttestOverTransport_RefusesAMalformedSignature proves the manual
// attestation path refuses a device that answers with a genuine, trusted
// chain but a signature that does not prove possession of it -- the same
// relay case TestPairRefusesAMalformedAttestationByDefault covers for
// pairing, now covered for the "Attest Device" RPC.
func TestAttestOverTransport_RefusesAMalformedSignature(t *testing.T) {
	h := newPairingHarness(t)
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	h.trust(ca)
	h.allowFixtureApplication()
	dak := healthyDAK(t, ca)
	device := attesttest.NewPhone(t, dak)

	transport, session, cfgDevice, done, cancel := h.attestReadyHarness(device, 1, testPairAddress)
	defer cancel()

	// Damage only the MANUAL exchange's answer; pairing above must still
	// have succeeded honestly.
	device.Mutate = func(r *pairing.LocalAttestDeviceResult) { r.Signature[0] ^= 0xff }

	ctx, exchangeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer exchangeCancel()

	result, err := h.svc.attestOverTransport(ctx, transport, session, cfgDevice)
	require.NoError(t, err, "a failed attestation is reported in the result, not as an error")
	require.NotNil(t, result)
	require.False(t, result.Verified)
	require.NotEmpty(t, result.ErrorMessage)

	cancel()
	select {
	case phoneErr := <-done:
		if !errors.Is(phoneErr, context.Canceled) {
			require.NoError(t, phoneErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("phone responder did not stop")
	}
}
