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

package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// Client side of the Noise bootstrap transport.
//
// ModeNoise used to reach the wire through go-truststrap's high-level
// truststrap.NewNoiseBootstrapper facade. That facade carries exactly one
// server key -- a 32-byte Curve25519 point -- and has no suite selector, so
// a client built through it can only ever offer Noise_NK, which mandates
// X25519 and is refused under FIPS by both mechanisms:
//
//	-tags fips                              → noise: X25519 is unavailable in FIPS build
//	GOFIPS140=v1.0.0 GODEBUG=fips140=only   → crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode
//
// The lower layer of the same module, noiseboot.Client, already negotiates
// both suites per connection and takes the P-256 responder key the approved
// suite needs. So ModeNoise composes that client directly, with the suite it
// offers resolved HERE by the same probe the listener uses
// (EnsureSuiteAvailable), never by a build-tag predicate: the shipped FIPS
// artifact is built with GOFIPS140 and no tag, so a tag-keyed rule would miss
// exactly the binary the policy cares about (go-xkms#436, go-xkms#269).
//
// This is deliberately the only place in the stack that composes
// noiseboot.Client for a fetch. go-truststrap#51 asks upstream to give its
// facade the same fields; when that lands, fetchNoise becomes pass-through
// again and this composition is removed.

// ErrSuiteKeyMissing reports a bootstrap suite that cannot be offered because
// no server public key is configured for it. It is the cause a SuiteError
// carries when the pinned suite has no key, and the reason NoSuiteError
// records for a suite that was simply not configured.
var ErrSuiteKeyMissing = errors.New("trust bootstrap: no server static key configured for suite")

// ErrSuiteKeyInvalid reports a configured server public key that is not a
// valid encoding for its suite: not hex, or the wrong length. A key that
// decodes but belongs to a different server is not detectable here; the
// handshake refuses it.
var ErrSuiteKeyInvalid = errors.New("trust bootstrap: server static key invalid for suite")

// ErrNoSuite reports that ModeNoise has no suite it can offer: every suite is
// either unconfigured or unavailable in this build. It is the sentinel to
// test with errors.Is; the NoSuiteError that carries it records the reason
// per suite.
var ErrNoSuite = errors.New("trust bootstrap: no bootstrap suite can be offered")

// ErrBundleMalformed reports a CA bundle response whose certificate list
// carries an entry that is not valid base64 DER. It is the sentinel behind
// BundleCertificateError.
var ErrBundleMalformed = errors.New("trust bootstrap: malformed certificate in CA bundle response")

// SuiteError reports a problem with one configured bootstrap suite, named so
// the operator knows which key or setting to fix. Cause is one of:
//
//   - ErrSuiteKeyMissing: the suite was pinned but no key is configured for it;
//   - ErrSuiteKeyInvalid (wrapping the decode failure): the key will not decode;
//   - ErrSuiteUnavailable (wrapping go-truststrap's refusal): the suite was
//     pinned but this build cannot run it, or the pinned value names no suite.
//     This is checked before any key, so it is the reason even when the key
//     is also missing: no key would help.
//
// A pinned suite never falls through to the other one: a FIPS client asked
// for Noise_NK gets this error, not a silent P-256 handshake, and vice versa.
type SuiteError struct {
	Suite byte
	Cause error
}

// Error implements error.
func (e *SuiteError) Error() string {
	return "trust bootstrap: suite " + suiteName(e.Suite) + ": " + e.Cause.Error()
}

// Unwrap exposes the cause so errors.Is reaches the sentinel behind it.
func (e *SuiteError) Unwrap() error { return e.Cause }

// NoSuiteError reports that no bootstrap suite survived resolution. Each field
// carries the reason its suite was rejected -- ErrSuiteKeyMissing when it was
// not configured, or the ErrSuiteUnavailable chain when the build cannot run
// it -- and both are exposed through Unwrap so errors.Is reaches them.
type NoSuiteError struct {
	// Noise is why Noise_NK_25519_ChaChaPoly_SHA256 cannot be offered.
	Noise error

	// P256 is why TSBOOT1_P256_AESGCM_SHA256 cannot be offered.
	P256 error
}

// Error implements error.
func (e *NoSuiteError) Error() string {
	return fmt.Sprintf("%s: %s: %v; %s: %v", ErrNoSuite.Error(),
		suiteName(SuiteNoiseNK), e.Noise, suiteName(SuiteP256AESGCM), e.P256)
}

// Is matches the ErrNoSuite sentinel.
func (e *NoSuiteError) Is(target error) bool { return target == ErrNoSuite }

// Unwrap exposes both rejection reasons.
func (e *NoSuiteError) Unwrap() []error { return []error{e.Noise, e.P256} }

// BundleCertificateError reports which entry of a CA bundle response failed
// to decode, and why. The bundle came over an authenticated channel, so a
// malformed entry is a server defect and the whole response is refused rather
// than silently thinned.
type BundleCertificateError struct {
	Index int
	Cause error
}

// Error implements error.
func (e *BundleCertificateError) Error() string {
	return fmt.Sprintf("%s: certificate %d: %v", ErrBundleMalformed.Error(), e.Index, e.Cause)
}

// Is matches the ErrBundleMalformed sentinel.
func (e *BundleCertificateError) Is(target error) bool { return target == ErrBundleMalformed }

// Unwrap exposes the decode failure.
func (e *BundleCertificateError) Unwrap() error { return e.Cause }

// noiseServerKeySize is the length of a Curve25519 public key, the form a
// Noise_NK client is provisioned with as the server's static key.
const noiseServerKeySize = 32

// ensureSuiteAvailable resolves whether this binary can run a suite. It is a
// variable for the reason pkg/server makes its own copy one: the "unavailable
// suite skipped" and "no suite at all" branches are real deployment states
// (a FIPS build) that a test binary's fixed build tags cannot reproduce, and
// injecting the refusal is the only way to cover them in every build. Tests
// restore it with a defer.
var ensureSuiteAvailable = EnsureSuiteAvailable

// suiteName returns the protocol name a suite byte selects, for error text.
func suiteName(suite byte) string {
	switch suite {
	case SuiteNoiseNK:
		return "Noise_NK_25519_ChaChaPoly_SHA256"
	case SuiteP256AESGCM:
		return p256proto.ProtocolName
	default:
		return fmt.Sprintf("0x%02x", suite)
	}
}

// noiseClientKeys holds the decoded server public keys ModeNoise will offer.
// A nil slice means that suite is not offered; resolveNoiseClientKeys
// guarantees at least one is set.
type noiseClientKeys struct {
	noise []byte
	p256  []byte
}

// resolveNoiseClientKeys decides which suites this client can offer and
// decodes the server public key for each.
//
// It distinguishes three outcomes that must not be conflated, in the same
// way the listener does (pkg/server.loadBootstrapKeys):
//
//   - A configured suite that is UNAVAILABLE in this build is skipped. That is
//     the expected state of Noise_NK under FIPS and is not an operator error --
//     unless the caller pinned that suite, in which case it is a SuiteError,
//     because the caller asked for something this build cannot do and must
//     not be handed the other suite instead.
//   - A configured, available suite whose key will not DECODE is a SuiteError.
//     Falling through to the other suite would let a typo in the pinned key
//     silently change which handshake runs.
//   - No suite surviving is a NoSuiteError carrying the reason for each.
//
// A pinned suite (cfg.Suite != 0) is resolved on its own: exactly that suite
// is offered, so exactly its key is required and decoded, and the other
// suite's key -- absent, stale or malformed -- is never consulted. Decoding
// both keys first would let a leftover Curve25519 value deny a client that
// pinned the approved suite and supplied a valid P-256 point, which is the
// opposite of what pinning promises.
func resolveNoiseClientKeys(cfg *NoiseConfig, logger *slog.Logger) (*noiseClientKeys, error) {
	// A pinned suite is checked against the build before any key is looked
	// at: if this binary cannot run it, no key would help, and the error
	// must name the build as the constraint. This also refuses a value that
	// names no suite at all.
	if cfg.Suite != 0 {
		if unavailable := ensureSuiteAvailable(cfg.Suite); unavailable != nil {
			return nil, &SuiteError{Suite: cfg.Suite, Cause: unavailable}
		}
		return resolvePinnedSuiteKey(cfg)
	}

	keys := &noiseClientKeys{}
	var noiseReason, p256Reason error

	if cfg.ServerStaticKey == "" {
		noiseReason = ErrSuiteKeyMissing
	} else if unavailable := ensureSuiteAvailable(SuiteNoiseNK); unavailable != nil {
		noiseReason = unavailable
		logger.Info("trust bootstrap: Noise_NK is unavailable in this build; offering the approved suite only",
			"reason", unavailable)
	} else {
		key, err := decodeSuiteKey(SuiteNoiseNK, cfg.ServerStaticKey, noiseServerKeySize)
		if err != nil {
			return nil, err
		}
		keys.noise = key
	}

	if cfg.ServerP256StaticKey == "" {
		p256Reason = ErrSuiteKeyMissing
	} else if unavailable := ensureSuiteAvailable(SuiteP256AESGCM); unavailable != nil {
		p256Reason = unavailable
		logger.Info("trust bootstrap: the approved suite is unavailable in this build",
			"reason", unavailable)
	} else {
		key, err := decodeSuiteKey(SuiteP256AESGCM, cfg.ServerP256StaticKey, P256PublicKeySize)
		if err != nil {
			return nil, err
		}
		keys.p256 = key
	}
	if keys.noise == nil && keys.p256 == nil {
		return nil, &NoSuiteError{Noise: noiseReason, P256: p256Reason}
	}
	return keys, nil
}

// resolvePinnedSuiteKey resolves the one key a pinned suite needs. The
// caller has already established that the build can run cfg.Suite, which
// also rules out a value naming no suite, so the remaining outcomes are the
// key being absent (ErrSuiteKeyMissing) or not decoding (ErrSuiteKeyInvalid).
func resolvePinnedSuiteKey(cfg *NoiseConfig) (*noiseClientKeys, error) {
	encoded, want := cfg.ServerStaticKey, noiseServerKeySize
	if cfg.Suite == SuiteP256AESGCM {
		encoded, want = cfg.ServerP256StaticKey, P256PublicKeySize
	}
	if encoded == "" {
		return nil, &SuiteError{Suite: cfg.Suite, Cause: ErrSuiteKeyMissing}
	}
	key, err := decodeSuiteKey(cfg.Suite, encoded, want)
	if err != nil {
		return nil, err
	}
	if cfg.Suite == SuiteP256AESGCM {
		return &noiseClientKeys{p256: key}, nil
	}
	return &noiseClientKeys{noise: key}, nil
}

// decodeSuiteKey decodes a hex-encoded server public key and checks it is the
// exact length its suite requires.
func decodeSuiteKey(suite byte, encoded string, want int) ([]byte, error) {
	key, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, &SuiteError{Suite: suite, Cause: fmt.Errorf("%w: %w", ErrSuiteKeyInvalid, err)}
	}
	if len(key) != want {
		return nil, &SuiteError{Suite: suite,
			Cause: fmt.Errorf("%w: got %d bytes, want %d", ErrSuiteKeyInvalid, len(key), want)}
	}
	return key, nil
}

// noiseClient adapts go-truststrap's suite-negotiating bootstrap client to
// the truststrap.Bootstrapper contract the dispatch already speaks, so
// fetchNoise goes through the same invoke path as every other mode.
type noiseClient struct {
	client *noiseboot.Client
	logger *slog.Logger
}

// newNoiseClient resolves the suites the client can offer and builds the
// upstream client around them. cfg.Suite is passed through: upstream applies
// its own FIPS policy on top of the keys resolved here, and the two agree by
// construction because an unavailable suite has no key left to select.
func newNoiseClient(addr string, cfg *NoiseConfig, timeout time.Duration, logger *slog.Logger) (*noiseClient, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	keys, err := resolveNoiseClientKeys(cfg, logger)
	if err != nil {
		return nil, err
	}

	// The facade this replaces defaulted the two timeouts separately; keep
	// its values so an unconfigured caller sees no behaviour change.
	connectTimeout := timeout
	if connectTimeout == 0 {
		connectTimeout = truststrap.DefaultNoiseConnectTimeout
	}
	operationTimeout := timeout
	if operationTimeout == 0 {
		operationTimeout = truststrap.DefaultNoiseOperationTimeout
	}

	client, err := noiseboot.NewClient(&noiseboot.ClientConfig{
		ServerAddr:          addr,
		ServerStaticKey:     keys.noise,
		ServerP256StaticKey: keys.p256,
		Suite:               cfg.Suite,
		ConnectTimeout:      connectTimeout,
		OperationTimeout:    operationTimeout,
		Logger:              logger,
	})
	if err != nil {
		return nil, err
	}
	return &noiseClient{client: client, logger: logger}, nil
}

// FetchCABundle runs one connection: handshake in the selected suite, one
// get_ca_bundle request, one response. Errors wrap truststrap.ErrFetchFailed
// exactly as the facade's did, so a caller classifying on that sentinel sees
// no change.
func (c *noiseClient) FetchCABundle(ctx context.Context, req *truststrap.CABundleRequest) (*truststrap.CABundleResponse, error) {
	if err := c.client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("%w: connect: %w", truststrap.ErrFetchFailed, err)
	}
	defer c.closeConn()

	storeType, algorithm := "", ""
	if req != nil {
		storeType, algorithm = req.StoreType, req.Algorithm
	}

	resp, err := c.client.GetCABundle(ctx, storeType, algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", truststrap.ErrFetchFailed, err)
	}

	certs := make([][]byte, 0, len(resp.Certificates))
	for i, encoded := range resp.Certificates {
		der, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			return nil, &BundleCertificateError{Index: i, Cause: decodeErr}
		}
		certs = append(certs, der)
	}

	return &truststrap.CABundleResponse{
		BundlePEM:    []byte(resp.BundlePEM),
		Certificates: certs,
		ContentType:  resp.ContentType,
	}, nil
}

// Close releases the connection if one is still open.
func (c *noiseClient) Close() error {
	return c.client.Close()
}

// closeConn closes the per-fetch connection. The fetch has already succeeded
// or failed by the time it runs, so a close failure changes nothing for the
// caller; it is logged rather than dropped.
func (c *noiseClient) closeConn() {
	if err := c.client.Close(); err != nil {
		c.logger.Debug("trust bootstrap: closing Noise bootstrap connection", "error", err)
	}
}
