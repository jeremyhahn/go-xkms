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

package avr

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------- construction

func TestNewBackendReadsCapsOnce(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)

	require.Len(t, link.requests, 1, "CAPS is read once on connect and cached")
	assert.Equal(t, aggeneric.CmdCaps, link.requests[0].Cmd())

	caps := b.Caps()
	assert.Equal(t, aggeneric.CryptoSecureElement, caps.CryptoTier)
	assert.True(t, caps.Has(aggeneric.FeatureAttest))
	assert.Equal(t, uint8(aggeneric.MaxPayload), caps.MaxPayload)

	// Capabilities answers from the cache and asks the device nothing.
	b.Capabilities()
	assert.Len(t, link.requests, 1)
}

func TestNewBackendRefusesAnIncompleteCall(t *testing.T) {
	ctx := context.Background()
	link := secureElementLink()

	_, err := NewBackend(ctx, nil, newTestDevice(link))
	assert.ErrorIs(t, err, ErrNilConfig)

	_, err = NewBackend(ctx, testConfig(), nil)
	assert.ErrorIs(t, err, ErrNilDevice)

	bad := testConfig()
	bad.KeyCN = ""
	_, err = NewBackend(ctx, bad, newTestDevice(link))
	assert.ErrorIs(t, err, ErrMissingKeyCN)

	assert.Empty(t, link.requests, "a configuration error costs no round trip")
}

// A device that is not there is not a backend. There is no useful degraded
// mode: every answer this backend gives comes from the device.
func TestNewBackendRefusesADeviceThatDoesNotAnswer(t *testing.T) {
	link := newFakeLink()
	link.readEOF = true

	_, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceUnreachable)
	assert.ErrorIs(t, err, io.EOF, "a closed port stays distinguishable from a stalled one")
}

func TestNewBackendRefusesALinkThatCannotBeWrittenTo(t *testing.T) {
	link := newFakeLink()
	link.writeErr = errors.New("port disappeared")

	_, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))

	assert.ErrorIs(t, err, ErrDeviceUnreachable)
}

// A frame whose checksum does not hold is not a reply. It must not be read as
// one, and it must not be read as a device that answered either.
func TestNewBackendRefusesACorruptedReply(t *testing.T) {
	link := secureElementLink()
	link.corrupt = true

	_, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceUnreachable,
		"a frame that never parses is a device that never answered")
}

// A CAPS reply too short for the header is the two ends disagreeing about a
// reply's shape, which the backend refuses rather than reading past.
func TestNewBackendRefusesAShortCapsReply(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, make([]byte, 9))

	_, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))

	assert.ErrorIs(t, err, ErrDeviceProtocol)
}

// A protocol MAJOR this host does not speak means the frames themselves may
// not parse the same way, so nothing past CAPS can be trusted to mean what it
// appears to mean.
func TestNewBackendRefusesAnUnsupportedProtocolMajor(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayloadWithProtocol(2, 0))

	_, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))

	assert.ErrorIs(t, err, ErrProtocolVersion)
}

// A protocol MINOR ahead of this host is tolerated in both directions. That is
// what lets a fleet run mixed firmware without a flag day.
func TestNewBackendAcceptsANewerProtocolMinor(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayloadWithProtocol(1, 9))

	b, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))
	require.NoError(t, err)
	require.NoError(t, b.Close())
}

// A crypto tier this host cannot classify is not a reason to refuse the
// device: tiers extend, and refusing here would take a fleet down on a host
// upgrade alone. The backend attaches, and reports unattested.
func TestNewBackendAttachesToADeviceWithAnUnknownTier(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps,
		capsPayload(aggeneric.CryptoTier(9), aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))

	b := newTestBackend(t, link)

	level, err := b.AttestLevel()
	assert.Equal(t, types.AttestLevelUnattested, level)
	assert.ErrorIs(t, err, ErrUnknownCryptoTier)
	assert.False(t, b.Capabilities().HardwareBacked)
}

// -------------------------------------------------------------- what it reports

func TestTypeIsAVR(t *testing.T) {
	b := newTestBackend(t, secureElementLink())

	assert.Equal(t, types.BackendTypeAVR, b.Type())
	assert.Equal(t, types.StoreAVR, types.ParseStoreType(string(b.Type())),
		"the backend's own type must round-trip through the store parser")
}

// The attestation level comes from the device's crypto tier and from nothing
// else -- not from the attestation feature bit, not from the algorithms on
// offer, not from anything the backend would prefer to be true.
func TestAttestLevelComesFromTheDeviceTier(t *testing.T) {
	tests := []struct {
		name     string
		tier     aggeneric.CryptoTier
		level    types.AttestLevel
		hardware bool
		security types.SecurityLevel
	}{
		{"none", aggeneric.CryptoNone, types.AttestLevelUnattested, false, types.SecurityLevelLow},
		{"software", aggeneric.CryptoSoftware, types.AttestLevelSoftware, false, types.SecurityLevelLow},
		{"secure element", aggeneric.CryptoSecureElement, types.AttestLevelHardware, true, types.SecurityLevelHigh},
		{"tpm2", aggeneric.CryptoTPM2, types.AttestLevelHardware, true, types.SecurityLevelVeryHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := newFakeLink().answer(aggeneric.CmdCaps,
				capsPayload(tt.tier, aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))
			b := newTestBackend(t, link)

			level, err := b.AttestLevel()
			require.NoError(t, err)
			assert.Equal(t, tt.level, level)

			caps := b.Capabilities()
			assert.Equal(t, tt.hardware, caps.HardwareBacked)
			assert.Equal(t, tt.security, caps.SecurityLevel)
		})
	}
}

// A device that claims the attestation feature but reports a software tier is
// still software. The feature bit says a command is compiled in; the tier says
// what the root of trust is, and only the second one is an attestation claim.
func TestAttestLevelIgnoresTheAttestationFeatureBit(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps,
		capsPayload(aggeneric.CryptoSoftware, aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))
	b := newTestBackend(t, link)

	level, err := b.AttestLevel()
	require.NoError(t, err)
	assert.Equal(t, types.AttestLevelSoftware, level)
	assert.True(t, b.Caps().Has(aggeneric.FeatureAttest))
}

// The algorithms this backend reports are the device's bitmap and nothing
// else. An ATECC608A has no hardware Ed25519; a host that advertised it here
// would negotiate a peer down onto an algorithm the element then fails.
func TestAlgorithmsComeFromTheDeviceBitmap(t *testing.T) {
	b := newTestBackend(t, secureElementLink())

	algs := b.Algorithms()
	assert.Equal(t, []Algorithm{AlgorithmECDSAP256SHA256, AlgorithmHMACSHA256}, algs.Named())
	assert.False(t, algs.Can(AlgorithmEd25519))
}

// Firmware built before the bitmap was appended sends a fourteen-byte reply,
// which is correct by the contract it was built against. It is read as
// claiming nothing rather than rejected.
func TestAlgorithmsAreEmptyForFirmwareOlderThanTheBitmap(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, legacyCapsPayload(aggeneric.CryptoSecureElement))
	b := newTestBackend(t, link)

	assert.True(t, b.Algorithms().Empty())
	assert.Empty(t, b.Algorithms().Named())
}

// Capabilities.Keys is false on purpose. The service's algorithm discovery
// advertises ECDSA at four curves, RSA at three key sizes and Ed25519 for
// every backend whose Keys is true -- which for this device would claim five
// algorithms it cannot perform and one its element has no hardware for.
func TestCapabilitiesDoNotClaimKeyGenerationOrSigning(t *testing.T) {
	b := newTestBackend(t, secureElementLink())
	caps := b.Capabilities()

	assert.False(t, caps.Keys, "the backend neither generates nor stores keys")
	assert.False(t, caps.Signing, "the wire has no command that signs a host-supplied digest")
	assert.False(t, caps.Decryption)
	assert.False(t, caps.KeyRotation)
	assert.False(t, caps.Import)
	assert.False(t, caps.Export)
	assert.False(t, caps.SymmetricEncryption)
	assert.False(t, caps.KeyAgreement)
	assert.True(t, caps.Attestation, "the device mints an alias certificate per challenge")
	assert.True(t, caps.HardwareBacked)
}

// ------------------------------------------------------------------- key access

func TestGetKeyReadsThePublicPointFromTheElement(t *testing.T) {
	point, pub := testPoint(t)
	link := secureElementLink().answer(aggeneric.CmdProvPubKey, point)
	b := newTestBackend(t, link)

	key, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})
	require.NoError(t, err)

	deviceKey, ok := key.(*DeviceKey)
	require.True(t, ok)
	assert.True(t, pub.Equal(deviceKey.Public()))

	// PROV_PUBKEY recomputes the point from the key already in the slot; the
	// generating command would have REPLACED the identity being asked about.
	last := link.requests[len(link.requests)-1]
	assert.Equal(t, aggeneric.CmdProvPubKey, last.Cmd())
	assert.Equal(t, []byte{aggeneric.SlotDeviceID}, last.Payload)
	for _, req := range link.requests {
		assert.NotEqual(t, aggeneric.CmdProvGenKey, req.Cmd(),
			"nothing here may reach the command that replaces the identity")
	}
}

// A production image has no provisioning handlers, by design: a device that
// can be re-provisioned over its own command channel has no identity worth
// attesting to. The refusal is reported as what it is, not as a fault.
func TestGetKeyReportsAProductionImageAsHavingNoHandler(t *testing.T) {
	link := secureElementLink() // no PROV_PUBKEY entry: answered ErrUnknownCmd
	b := newTestBackend(t, link)

	_, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})

	assert.ErrorIs(t, err, ErrCommandUnavailable)
}

func TestGetKeyReportsAnUnprovisionedDevice(t *testing.T) {
	link := secureElementLink().refuse(aggeneric.CmdProvPubKey, aggeneric.StatusErrNotProvisioned)
	b := newTestBackend(t, link)

	_, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})

	assert.ErrorIs(t, err, ErrNotProvisioned)
}

func TestGetKeyRefusesAPointTheDeviceCouldNotHaveMeant(t *testing.T) {
	link := secureElementLink().answer(aggeneric.CmdProvPubKey, make([]byte, devicePointLen))
	b := newTestBackend(t, link)

	_, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})

	assert.ErrorIs(t, err, ErrInvalidDevicePoint)
}

func TestGetKeyRefusesAnythingButTheConfiguredName(t *testing.T) {
	point, _ := testPoint(t)
	link := secureElementLink().answer(aggeneric.CmdProvPubKey, point)
	b := newTestBackend(t, link)

	before := len(link.requests)
	_, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: "some-other-key"})

	require.ErrorIs(t, err, ErrUnknownKey)
	assert.Contains(t, err.Error(), "some-other-key")
	assert.Len(t, link.requests, before, "an unknown name costs no round trip")
}

func TestGetKeyRefusesNilAttributes(t *testing.T) {
	b := newTestBackend(t, secureElementLink())

	_, err := b.GetKey(context.Background(), nil)

	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// A device with no crypto provider holds no identity, so there is nothing to
// read and nothing to ask for.
func TestGetKeyRefusesWhenTheDeviceHasNoProvider(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayload(aggeneric.CryptoNone, 0, 0))
	b := newTestBackend(t, link)

	before := len(link.requests)
	_, err := b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})

	assert.ErrorIs(t, err, ErrNoDeviceKey)
	assert.Len(t, link.requests, before)
}

func TestListKeysDescribesTheOneKeyTheDeviceHolds(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)

	before := len(link.requests)
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, DefaultKeyCN, key.CN)
	assert.Equal(t, types.StoreAVR, key.StoreType)
	assert.Equal(t, types.AttestLevelHardware, key.AttestLevel)
	assert.Equal(t, types.KeyTypeIDevID, key.KeyType)
	assert.False(t, key.Exportable)
	assert.True(t, key.Sensitive)
	assert.Len(t, link.requests, before, "the inventory is already known")
}

// The attestation level stamped on the record follows the device, so a
// software-tier part is recorded as software rather than as the hardware the
// backend would prefer to claim.
func TestListKeysStampsTheDeviceAttestLevel(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps,
		capsPayload(aggeneric.CryptoSoftware, aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))
	b := newTestBackend(t, link)

	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, types.AttestLevelSoftware, keys[0].AttestLevel)
}

func TestListKeysIsEmptyWhenTheDeviceHasNoProvider(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps, capsPayload(aggeneric.CryptoNone, 0, 0))
	b := newTestBackend(t, link)

	keys, err := b.ListKeys(context.Background())

	require.NoError(t, err)
	assert.Empty(t, keys)
}

// ------------------------------------------------------------------- refusals

// Every one of these is a permanent property of the part or the protocol, not
// a gap. Each refuses without touching the wire: a round trip to be told what
// is already known would only make the failure slower.
func TestUnsupportedOperationsRefuseWithoutTouchingTheWire(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)
	ctx := context.Background()
	attrs := &types.KeyAttributes{CN: DefaultKeyCN}
	before := len(link.requests)

	_, err := b.GenerateKey(ctx, attrs)
	assert.ErrorIs(t, err, ErrGenerationUnsupported)

	_, err = b.Signer(ctx, attrs)
	assert.ErrorIs(t, err, ErrSigningUnsupported)

	_, err = b.Decrypter(ctx, attrs)
	assert.ErrorIs(t, err, ErrDecryptionUnsupported)

	assert.ErrorIs(t, b.DeleteKey(ctx, attrs), ErrDeletionUnsupported)
	assert.ErrorIs(t, b.RotateKey(ctx, attrs), ErrRotationUnsupported)

	assert.Len(t, link.requests, before)
}

// -------------------------------------------------------------------- lifecycle

func TestHealthReportsRuntimeStateAndNotATimestamp(t *testing.T) {
	link := secureElementLink().answer(aggeneric.CmdSysInfo,
		sysInfoPayload(90*time.Second, 1234, aggeneric.ResetWatchdog))
	b := newTestBackend(t, link)

	health, err := b.Health(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 90*time.Second, health.Uptime)
	assert.Equal(t, uint16(1234), health.FreeRAM)
	assert.Equal(t, aggeneric.ResetWatchdog, health.ResetCause)
}

func TestHealthReportsADeviceThatWillNotAnswer(t *testing.T) {
	link := secureElementLink().refuse(aggeneric.CmdSysInfo, aggeneric.StatusErrInternal)
	b := newTestBackend(t, link)

	_, err := b.Health(context.Background())

	assert.ErrorIs(t, err, ErrDeviceInternal)
}

// Close does not close the link: the caller opened it and may still be using
// it for the device's other concerns.
func TestCloseLeavesTheLinkToItsOwner(t *testing.T) {
	link := secureElementLink()
	b, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))
	require.NoError(t, err)

	require.NoError(t, b.Close())
	require.NoError(t, b.Close(), "closing twice is not an error")

	_, err = link.Write(mustEncodePing(t))
	assert.NoError(t, err, "the link is still the caller's to use")
}

// Every entry point refuses after Close. A backend that answered from its
// cache after being closed would report a device nobody is talking to any
// more.
func TestEveryOperationRefusesAfterClose(t *testing.T) {
	b, err := NewBackend(context.Background(), testConfig(), newTestDevice(secureElementLink()))
	require.NoError(t, err)
	require.NoError(t, b.Close())

	ctx := context.Background()
	attrs := &types.KeyAttributes{CN: DefaultKeyCN}

	_, err = b.GenerateKey(ctx, attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = b.GetKey(ctx, attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = b.ListKeys(ctx)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = b.Signer(ctx, attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = b.Decrypter(ctx, attrs)
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = b.Health(ctx)
	assert.ErrorIs(t, err, ErrBackendClosed)

	assert.ErrorIs(t, b.DeleteKey(ctx, attrs), ErrBackendClosed)
	assert.ErrorIs(t, b.RotateKey(ctx, attrs), ErrBackendClosed)
}

// A cancelled context stops the exchange and stays reachable as itself, so a
// caller's own select on context.Canceled still works through the backend.
func TestGetKeyHonoursACancelledContext(t *testing.T) {
	point, _ := testPoint(t)
	link := secureElementLink().answer(aggeneric.CmdProvPubKey, point)
	b := newTestBackend(t, link)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.GetKey(ctx, &types.KeyAttributes{CN: DefaultKeyCN})

	assert.ErrorIs(t, err, context.Canceled)
}

func mustEncodePing(t *testing.T) []byte {
	t.Helper()
	frame, err := aggeneric.EncodeRequest(1, aggeneric.CmdPing, nil)
	require.NoError(t, err)
	return frame
}

// A tier this host cannot classify holds no key it can describe. Handing out
// an identity whose backing cannot be stated would put an unattested key into
// a record that has nowhere to say so.
func TestADeviceWithAnUnknownTierExposesNoKey(t *testing.T) {
	link := newFakeLink().answer(aggeneric.CmdCaps,
		capsPayload(aggeneric.CryptoTier(9), aggeneric.FeatureAttest, aggeneric.AlgECDSAP256SHA256))
	b := newTestBackend(t, link)
	before := len(link.requests)

	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	_, err = b.GetKey(context.Background(), &types.KeyAttributes{CN: DefaultKeyCN})
	assert.ErrorIs(t, err, ErrNoDeviceKey)
	assert.Len(t, link.requests, before)
}

// ------------------------------------------------------------ element identity

func TestIdentityReadsTheElementSerialAndLockState(t *testing.T) {
	serial := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x5A}
	link := secureElementLink().answer(aggeneric.CmdProvInfo,
		provInfoPayload(serial, true, true))
	b := newTestBackend(t, link)

	id, err := b.Identity(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "0123456789abcdef5a", id.Serial)
	assert.Equal(t, serial, id.SerialBytes)
	assert.True(t, id.ConfigLocked)
	assert.True(t, id.DataLocked)
	assert.True(t, id.Provisioned())
	assert.Contains(t, id.String(), "0123456789abcdef5a")
}

// 0x55 is the element's UNLOCKED value, so the byte that looks like a flag
// being set is the zone being OPEN. Inverting this would report every blank
// part as provisioned, which is the direction that matters: a blank part read
// as finished is an identity nobody wrote being trusted.
func TestIdentityDoesNotInvertTheLockPolarity(t *testing.T) {
	serial := make([]byte, 9)
	link := secureElementLink().answer(aggeneric.CmdProvInfo,
		provInfoPayload(serial, false, false))
	b := newTestBackend(t, link)

	id, err := b.Identity(context.Background())
	require.NoError(t, err)

	assert.False(t, id.ConfigLocked, "0x55 means the zone is open")
	assert.False(t, id.DataLocked)
	assert.False(t, id.Provisioned())
}

// A part with a locked config zone and an open data zone is part-way through
// provisioning: neither a blank nor a finished device, and it must not be
// mistaken for either.
func TestIdentityDistinguishesAPartlyProvisionedPart(t *testing.T) {
	serial := make([]byte, 9)
	link := secureElementLink().answer(aggeneric.CmdProvInfo,
		provInfoPayload(serial, true, false))
	b := newTestBackend(t, link)

	id, err := b.Identity(context.Background())
	require.NoError(t, err)

	assert.True(t, id.ConfigLocked)
	assert.False(t, id.DataLocked)
	assert.False(t, id.Provisioned())
}

// A production image has no provisioning handlers, by design. The refusal is
// reported as what it is, which is why the device record is keyed on the
// public key and not on this.
func TestIdentityReportsAProductionImageAsHavingNoHandler(t *testing.T) {
	b := newTestBackend(t, secureElementLink())

	_, err := b.Identity(context.Background())

	assert.ErrorIs(t, err, ErrCommandUnavailable)
}

// The firmware cannot tell an absent element from one whose bus is miswired or
// clocked too fast for the wake pulse, so it points at the bus. That is a
// different fault from a device that did not answer at all.
func TestIdentityReportsAnElementThatWillNotWake(t *testing.T) {
	link := secureElementLink().refuse(aggeneric.CmdProvInfo, aggeneric.StatusErrNACK)
	b := newTestBackend(t, link)

	_, err := b.Identity(context.Background())

	require.ErrorIs(t, err, ErrElementUnreachable)
	assert.NotErrorIs(t, err, ErrDeviceUnreachable)
}

// Firmware older than the lock-byte fix sends 36 bytes. It is refused as a
// short reply rather than read past -- the defect this replaced indexed byte
// 90 of a 36-byte payload and panicked on every legal answer.
func TestIdentityRefusesAReplyWithoutTheLockBytes(t *testing.T) {
	link := secureElementLink().answer(aggeneric.CmdProvInfo, make([]byte, 36))
	b := newTestBackend(t, link)

	_, err := b.Identity(context.Background())

	assert.ErrorIs(t, err, ErrDeviceProtocol)
}

func TestIdentityRefusesAfterClose(t *testing.T) {
	b, err := NewBackend(context.Background(), testConfig(), newTestDevice(secureElementLink()))
	require.NoError(t, err)
	require.NoError(t, b.Close())

	_, err = b.Identity(context.Background())

	assert.ErrorIs(t, err, ErrBackendClosed)
}
