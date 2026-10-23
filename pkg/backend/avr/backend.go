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
	"crypto"
	"crypto/x509"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface satisfaction check. Backend is a KeyProvider and
// deliberately not a types.AttestingKeyProvider; see the package
// documentation.
var _ types.KeyProvider = (*Backend)(nil)

// Backend is one attached AVR device, presented as an xkms key provider.
//
// It holds no private key and needs no locked memory: the identity's private
// half is inside the element and the wire defines no command that would let it
// out. What this type holds is the device's CAPS reply, read once on
// construction and never re-read.
//
// Caching CAPS is not an optimisation, it is what makes Capabilities
// answerable. types.KeyProvider.Capabilities returns no error, so a backend
// that had to ask the device what it was every time would have to invent an
// answer whenever the device did not reply — and the invented answer would be
// about the strength of a root of trust. Asking once, at construction, means a
// backend either exists and knows what it is talking to, or does not exist.
type Backend struct {
	config *Config
	logger *slog.Logger

	// wire serialises every command against the device.
	//
	// A mutex rather than a lock-free scheme because the thing being protected
	// is not a word of state, it is a CONVERSATION. aggeneric.Device is a
	// strict request/response client over one link: Do allocates the next
	// sequence number, writes, then reads until a frame carrying that sequence
	// arrives, collecting events and discarding replies to other sequences on
	// the way. Two goroutines in Do at once therefore consume each other's
	// replies, and the loser sees a timeout rather than an answer. AttestCert
	// is worse: it is several Do calls that must stay CONTIGUOUS, because the
	// device regenerates its pages on each new nonce and keeps no copy -- a
	// second attestation interleaved between two page reads splices two
	// certificates into one buffer.
	//
	// The device's own SDK says so ("must not be called concurrently on one
	// device"), and types.KeyProvider requires implementations to be
	// thread-safe. This is where those two meet.
	wire   sync.Mutex
	device *aggeneric.Device

	caps aggeneric.Caps

	// roots and intermediates are resolved once, at construction, from
	// Config.Attestation. A trust store that failed to load is a backend that
	// fails to build: discovering it at the first attestation would mean
	// discovering it in front of a device that is waiting to enrol.
	roots         *x509.CertPool
	intermediates *x509.CertPool
	// intermediateCerts is the same set as a chain, for dice.Verify.
	intermediateCerts []*x509.Certificate

	closed atomic.Bool
}

// NewBackend connects the backend to an already-open device.
//
// The device is the caller's: this backend does not own the serial port, the
// pipe or whatever else is underneath, and Close does not close it. That
// mirrors how a device is actually used — one link, several concerns — and
// keeps the lifetime with the code that opened it.
//
// Construction reads CAPS, so it fails when the device is not there, does not
// answer, or speaks a protocol major this host cannot parse. A device that
// cannot say what it is is not a backend.
func NewBackend(ctx context.Context, config *Config, device *aggeneric.Device) (*Backend, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrNilDevice
	}

	// Config.RequestTimeout has to reach the device or it is not the request
	// timeout.
	//
	// Device.Do computes its read deadline from the device's OWN timeout,
	// default ten seconds, and only notices a context between reads -- so a
	// blocking read on a real serial port runs to that deadline whatever the
	// context says. A configured thirty seconds that still gave up at ten would
	// be a setting that reads as honoured and is not, and the part it was
	// raised for is the one deriving a key in software for several seconds on a
	// 16 MHz core.
	//
	// aggeneric.Option is the SDK's own way to set it and is a plain
	// func(*Device), so it applies here as well as at New. The device is the
	// caller's and this does change it: a backend that issues every command on
	// that link owns the deadline those commands are given, and the alternative
	// is a Config field that lies.
	aggeneric.WithTimeout(config.RequestTimeout)(device)

	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()

	caps, err := device.Caps(ctx)
	if err != nil {
		// Caps returns what the device said ALONGSIDE a version error, and
		// that is the one thing worth logging when a host refuses to talk to
		// a device — but it is not a reason to proceed, because on a major
		// mismatch the frames themselves may not parse the same way.
		return nil, deviceError(err)
	}
	if caps == nil {
		return nil, deviceError(aggeneric.StatusErrInternal)
	}

	logger := config.Logger.With("component", "avr_backend")
	b := &Backend{
		config: config,
		device: device,
		caps:   *caps,
		logger: logger,
	}
	if err := b.initAttestation(); err != nil {
		return nil, err
	}

	level, levelErr := b.AttestLevel()
	logger.Info("avr device attached",
		"protocol", protocolString(*caps),
		"firmware", firmwareString(*caps),
		"board_id", caps.BoardID,
		"crypto_tier", caps.CryptoTier.String(),
		"attest_level", level.String(),
		"algorithms", caps.Algorithms.String(),
		"attestation_feature", caps.Has(aggeneric.FeatureAttest),
	)
	if levelErr != nil {
		// Not fatal, and deliberately so. Tiers extend, so a host older than
		// the firmware it meets is the ordinary state of a fleet mid-upgrade
		// and refusing here would take that fleet down on a host upgrade
		// alone. The level has already degraded to unattested, which is the
		// safe direction; this says out loud that it did.
		logger.Warn("device reports a crypto tier this host cannot classify",
			"crypto_tier", uint8(caps.CryptoTier),
			"error", levelErr,
		)
	}

	return b, nil
}

// initAttestation resolves the trust anchors an alias certificate must descend
// from. A nil Attestation leaves both pools nil, which AttestKey reports as
// Anchored false rather than treating as an anchor that matched.
func (b *Backend) initAttestation() error {
	if b.config.Attestation == nil {
		return nil
	}

	if len(b.config.Attestation.Intermediates) > 0 {
		pool := x509.NewCertPool()
		for i, der := range b.config.Attestation.Intermediates {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return &errs.Joined{
					Lead:   ErrTrustStoreInit,
					Detail: "intermediate " + strconv.Itoa(i),
					Cause:  err,
				}
			}
			pool.AddCert(cert)
			// Kept as certificates as well as in a pool: dice.Verify takes a
			// CHAIN and builds its own pool, because it must strip the DICE
			// critical extensions from each link first. A pool cannot be walked
			// back into certificates.
			b.intermediateCerts = append(b.intermediateCerts, cert)
		}
		b.intermediates = pool
	}

	if b.config.Attestation.TrustStore == nil {
		return nil
	}
	store, err := truststore.New(b.config.Attestation.TrustStore)
	if err != nil {
		return &errs.Joined{Lead: ErrTrustStoreInit, Cause: err}
	}
	roots, err := store.CertPool()
	if err != nil {
		return &errs.Joined{Lead: ErrTrustStoreInit, Cause: err}
	}
	count, err := store.Count()
	if err != nil {
		return &errs.Joined{Lead: ErrTrustStoreInit, Cause: err}
	}
	b.roots = roots

	b.logger.Info("avr attestation anchoring enabled",
		"roots", count,
		"intermediates", len(b.config.Attestation.Intermediates),
	)
	return nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType { return types.BackendTypeAVR }

// Capabilities reports what this backend can do, derived from what the device
// said about itself.
//
// Keys is FALSE, and that is the point rather than an omission. The flag reads
// as "generates and stores keys", and this backend does neither: the identity
// is created on a provisioning jig, inside a locked element, by firmware that
// is replaced before the part ships. Reporting it true would also make the
// service's algorithm discovery advertise ECDSA at four curve sizes, RSA at
// three key sizes and Ed25519 on this backend's behalf — for a part whose own
// bitmap says ECDSA P-256 and nothing else, and whose element has no hardware
// Ed25519 at all. Callers that want to know what the device can perform ask
// Algorithms, which answers from the device's bitmap.
//
// Attestation is TRUE: AttestKey asks the device to mint an alias certificate
// carrying the verifier's challenge, which is the DICE evidence path.
func (b *Backend) Capabilities() types.Capabilities {
	trust, _ := trustFor(b.caps.CryptoTier)
	return types.Capabilities{
		Keys:                false,
		HardwareBacked:      trust.hardware,
		Signing:             false,
		Decryption:          false,
		KeyRotation:         false,
		SymmetricEncryption: false,
		Sealing:             false,
		Import:              false,
		Export:              false,
		KeyAgreement:        false,
		ECIES:               false,
		Attestation:         true,
		QuantumSigning:      false,
		KeyEncapsulation:    false,
		SecurityLevel:       trust.security,
		// The device attests; it generates no keys (see Algorithms for what
		// its crypto provider performs).
		KeyAlgorithms: types.KeyAlgorithms{},
	}
}

// Caps returns the device's CAPS reply as it was read at construction.
func (b *Backend) Caps() aggeneric.Caps { return b.caps }

// Algorithms reports what the device's crypto provider can perform, from the
// device's own CAPS bitmap.
func (b *Backend) Algorithms() Algorithms { return Algorithms{set: b.caps.Algorithms} }

// AttestLevel reports what the device's crypto tier establishes about the keys
// behind it.
//
// This is the backend's answer to "is this key hardware-backed", and it comes
// from one field of the device's own CAPS reply. It returns
// ErrUnknownCryptoTier, with types.AttestLevelUnattested, for a tier this host
// has no classification for — never hardware on the assumption that a higher
// number is a stronger one.
func (b *Backend) AttestLevel() (types.AttestLevel, error) {
	trust, known := trustFor(b.caps.CryptoTier)
	if !known {
		return types.AttestLevelUnattested, &errs.Detail{
			Err:    ErrUnknownCryptoTier,
			Detail: b.caps.CryptoTier.String(),
		}
	}
	return trust.level, nil
}

// Identity reads the element's hardware identity: its serial number, its die
// revision and the lock state of both zones. Reading it writes nothing.
//
// On a production image it is refused with ErrCommandUnavailable, because the
// provisioning commands are compiled out of the firmware a part ships with --
// a device that can be re-provisioned over its own command channel has no
// identity worth recording. That is the ordinary answer from a fielded device
// and not a fault, which is why the device record is keyed on the identity
// public key and this is a bench-time cross-check rather than the key.
func (b *Backend) Identity(ctx context.Context) (*Identity, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	// The deadline is set AFTER the wire is acquired, not before: RequestTimeout
	// bounds this call's own exchange with the device, and a queue of other
	// legitimate callers serialised ahead of it on the same wire is not part of
	// that exchange. A deadline started before Lock would count time spent
	// waiting behind them against the caller that did the waiting, so enough
	// concurrent callers would make every one but the first fail on a device
	// that answered every request it received.
	b.wire.Lock()
	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	info, err := b.device.ProvInfo(ctx)
	cancel()
	b.wire.Unlock()
	if err != nil {
		return nil, deviceError(err)
	}
	return newIdentity(info), nil
}

// Health reads the device's runtime state.
//
// Nothing here is a timestamp: the part has no clock. Uptime and the reset
// cause say how long it has been running and why it last restarted, which is
// how a device that keeps resetting is told from one that is simply up.
func (b *Backend) Health(ctx context.Context) (*Health, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	// See the comment in Identity: the deadline starts once the wire is ours,
	// not before, so queueing behind other concurrent callers is not charged
	// against this call's own timeout.
	b.wire.Lock()
	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	info, err := b.device.SysInfo(ctx)
	cancel()
	b.wire.Unlock()
	if err != nil {
		return nil, deviceError(err)
	}
	return &Health{
		Uptime:     info.Uptime,
		FreeRAM:    info.FreeRAM,
		ResetCause: info.ResetCause,
	}, nil
}

// GenerateKey is refused.
//
// Generating the identity keypair replaces the device's identity. The command
// that does it exists only in a provisioning jig's firmware and is gone from
// the image a part ships with, deliberately: whoever can re-provision a device
// over its own serial line is its manufacturer. A key provider that reached it
// would destroy the thing every other answer here is about.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	return nil, ErrGenerationUnsupported
}

// GetKey returns a handle on the device's identity key, with the public point
// read from the element.
//
// The returned handle is a *DeviceKey and is not a crypto.Signer: see
// Backend.Signer.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if attrs.CN != b.config.KeyCN {
		return nil, &errs.Detail{Err: ErrUnknownKey, Detail: attrs.CN}
	}
	if !b.hasDeviceKey() {
		return nil, ErrNoDeviceKey
	}

	// ProvPubKey RECOMPUTES the public point from the private key already in
	// the slot. It generates nothing, which is what makes it safe to call
	// against a provisioned part -- unlike ProvGenKey, which would replace the
	// identity it was asked about.
	//
	// See the comment in Identity: the deadline starts once the wire is ours,
	// not before, so queueing behind other concurrent callers is not charged
	// against this call's own timeout.
	b.wire.Lock()
	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	point, err := b.device.ProvPubKey(ctx, b.config.Slot)
	cancel()
	b.wire.Unlock()
	if err != nil {
		return nil, deviceError(err)
	}
	return newDeviceKey(point, b.config.Slot, b.config.KeyCN)
}

// DeleteKey is refused. The identity lives in a zone of the element that is
// locked irreversibly during provisioning; there is no command that erases it
// and no state the part can be returned to.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}
	return ErrDeletionUnsupported
}

// ListKeys returns the one key an AVR device holds, or nothing when the device
// reports no crypto provider at all.
//
// It asks the device nothing: whether an identity key exists follows from the
// crypto tier already read at construction, and the attributes are metadata.
// The public point is read by GetKey, which is where a caller has said it
// wants the key rather than the inventory.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !b.hasDeviceKey() {
		return []*types.KeyAttributes{}, nil
	}
	return []*types.KeyAttributes{b.keyAttributes()}, nil
}

// Signer is refused, and the refusal is the honest answer rather than a gap.
//
// The wire protocol defines no command that signs a digest the host supplied,
// on purpose. The device signs its own attestation evidence and its own alias
// certificate, both of which it builds itself from values it can account for.
// A signature over 32 opaque bytes a host handed it would be a signature over
// whatever the holder of those bytes says it is, which would make the device's
// identity key a general-purpose signing oracle for anyone who reached the
// serial line.
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	return nil, ErrSigningUnsupported
}

// Decrypter is refused. The element's key is a signing identity and the wire
// defines no decryption command.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	return nil, ErrDecryptionUnsupported
}

// RotateKey is refused, for the same reason as DeleteKey. A new identity on
// this part means a new part.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if b.closed.Load() {
		return ErrBackendClosed
	}
	return ErrRotationUnsupported
}

// Close marks the backend closed. The link underneath belongs to the caller
// who opened it and is not closed here.
func (b *Backend) Close() error {
	b.closed.Store(true)
	return nil
}

// hasDeviceKey reports whether the device has a crypto provider to hold an
// identity at all. A tier this host cannot classify counts as no key: an
// identity whose backing cannot be described is not one to hand out.
func (b *Backend) hasDeviceKey() bool {
	trust, known := trustFor(b.caps.CryptoTier)
	if !known {
		return false
	}
	return trust.level != types.AttestLevelUnattested
}

func protocolString(c aggeneric.Caps) string {
	return strconv.Itoa(int(c.ProtoMajor)) + "." + strconv.Itoa(int(c.ProtoMinor))
}

func firmwareString(c aggeneric.Caps) string {
	return strconv.Itoa(int(c.FirmwareMajor)) + "." +
		strconv.Itoa(int(c.FirmwareMinor)) + "." +
		strconv.Itoa(int(c.FirmwarePatch))
}
