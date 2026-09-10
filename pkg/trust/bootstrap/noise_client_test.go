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
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run in EVERY build -- ordinary, -tags fips, and
// GOFIPS140 + GODEBUG=fips140=only -- and key their expectations on what the
// binary can actually run (noiseRunnable), never on a build tag. The claims a
// FIPS build must uniquely satisfy are in noise_client_fips_test.go.

// placeholderNoiseKey is a syntactically valid Noise server key for a client
// configuration in a build that cannot run Noise_NK: it must be skipped, not
// decoded, so its value never matters.
var placeholderNoiseKey = strings.Repeat("ab", noiseServerKeySize)

// testBundler serves a fixed PEM bundle to the bootstrap listener.
type testBundler struct{ pem []byte }

func (b *testBundler) CABundle() ([]byte, error) { return b.pem, nil }

// bootstrapListener is a real go-truststrap listener with the server keys the
// build can hold: always a P-256 key, plus a Noise key when Noise is runnable
// and the test asked for one.
type bootstrapListener struct {
	addr     string
	pem      []byte
	noiseHex string // "" when the listener offers no Noise_NK
	p256Hex  string
}

// startListener starts a listener offering the approved suite and, when
// withNoise is set and the build can run it, Noise_NK too. Suites are offered
// by handing the server a key; the negotiation is upstream's.
func startListener(t *testing.T, withNoise bool) *bootstrapListener {
	t.Helper()

	p256Key, err := GenerateP256StaticKey()
	require.NoError(t, err)
	t.Cleanup(p256Key.Destroy)

	cfg := &NoiseServerConfig{
		ListenAddr:    "127.0.0.1:0",
		P256StaticKey: p256Key,
		CABundler:     &testBundler{pem: newTestPEMBundle(t)},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l := &bootstrapListener{p256Hex: hex.EncodeToString(p256Key.PublicBytes())}

	if withNoise && noiseRunnable(t) {
		noiseKey, err := GenerateNoiseStaticKey()
		require.NoError(t, err)
		t.Cleanup(noiseKey.Destroy)
		cfg.StaticKey = NoiseServerStaticKey(noiseKey)
		l.noiseHex = hex.EncodeToString(noiseKey.Public)
	}

	srv, err := NewNoiseServer(cfg)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	l.addr = srv.Addr().String()
	l.pem = cfg.CABundler.(*testBundler).pem
	return l
}

func fetchNoiseFrom(t *testing.T, l *bootstrapListener, noise *NoiseConfig) (*CABundle, error) {
	t.Helper()
	if noise.ServerAddr == "" {
		noise.ServerAddr = l.addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Fetch(ctx, Config{
		Mode:             ModeNoise,
		Noise:            noise,
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
	})
}

func requireBundle(t *testing.T, l *bootstrapListener, bundle *CABundle) {
	t.Helper()
	require.NotNil(t, bundle)
	assert.Equal(t, string(l.pem), string(bundle.PEM), "the bundle must round-trip byte for byte")
	assert.Len(t, bundle.Certificates, 2, "both DER certificates must be decoded")
	assert.Equal(t, "application/pem-certificate-chain", bundle.ContentType)
}

// =============================================================================
// Real handshakes through Fetch(ModeNoise)
// =============================================================================

// The approved suite must complete a real bootstrap in EVERY build. This is
// the client half of go-xkms#269: a listener offering only P-256, a client
// provisioned with only the P-256 responder key, and the bundle round-trips.
func TestFetch_NoiseP256OnlyCompletesInEveryBuild(t *testing.T) {
	l := startListener(t, false)

	bundle, err := fetchNoiseFrom(t, l, &NoiseConfig{ServerP256StaticKey: l.p256Hex})
	require.NoError(t, err)
	requireBundle(t, l, bundle)
}

// A client holding BOTH keys must complete in every build: the policy picks
// Noise_NK where it can run and the approved suite where it cannot. The
// listener offers only P-256 when Noise is unavailable, so in that build the
// only way this passes is by skipping the Noise key rather than failing on it.
func TestFetch_NoiseBothKeysConfiguredCompletesInEveryBuild(t *testing.T) {
	l := startListener(t, true)

	noiseKey := l.noiseHex
	if noiseKey == "" {
		noiseKey = placeholderNoiseKey
	}
	bundle, err := fetchNoiseFrom(t, l, &NoiseConfig{
		ServerStaticKey:     noiseKey,
		ServerP256StaticKey: l.p256Hex,
	})
	require.NoError(t, err)
	requireBundle(t, l, bundle)
}

// Pinning the approved suite must run it even when Noise_NK is also
// configured and runnable.
func TestFetch_NoisePinnedP256RunsP256(t *testing.T) {
	l := startListener(t, true)

	noiseKey := l.noiseHex
	if noiseKey == "" {
		noiseKey = placeholderNoiseKey
	}
	bundle, err := fetchNoiseFrom(t, l, &NoiseConfig{
		ServerStaticKey:     noiseKey,
		ServerP256StaticKey: l.p256Hex,
		Suite:               SuiteP256AESGCM,
	})
	require.NoError(t, err)
	requireBundle(t, l, bundle)
}

// The Noise_NK path this change replaces must keep working UNCHANGED where
// the build can run it: a listener offering only Noise_NK, a client holding
// only the Curve25519 key, exactly the configuration every existing deployment
// has. Where the build cannot run Noise the same configuration must be the
// typed "no suite" refusal, not a hang or a silent P-256 attempt.
func TestFetch_NoiseNKOnlyIsUnchangedWhereRunnable(t *testing.T) {
	if !noiseRunnable(t) {
		l := startListener(t, false)
		_, err := fetchNoiseFrom(t, l, &NoiseConfig{ServerStaticKey: placeholderNoiseKey})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrFetch)
		assert.ErrorIs(t, err, ErrNoSuite)
		assert.ErrorIs(t, err, ErrSuiteUnavailable, "the refusal must carry the build's reason")
		return
	}

	// A Noise-only listener: build it directly so it has NO P-256 key and the
	// handshake can only have been Noise_NK.
	noiseKey, err := GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer noiseKey.Destroy()
	pem := newTestPEMBundle(t)
	srv, err := NewNoiseServer(&NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  NoiseServerStaticKey(noiseKey),
		CABundler:  &testBundler{pem: pem},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	l := &bootstrapListener{addr: srv.Addr().String(), pem: pem}
	bundle, err := fetchNoiseFrom(t, l, &NoiseConfig{ServerStaticKey: hex.EncodeToString(noiseKey.Public)})
	require.NoError(t, err)
	requireBundle(t, l, bundle)

	// And pinning it explicitly is the same handshake.
	bundle, err = fetchNoiseFrom(t, l, &NoiseConfig{
		ServerStaticKey: hex.EncodeToString(noiseKey.Public),
		Suite:           SuiteNoiseNK,
	})
	require.NoError(t, err)
	requireBundle(t, l, bundle)
}

// A wrong (but well-formed) responder key must fail the handshake, wrapped
// in the same sentinels the facade used so callers classifying on them see
// no change.
func TestFetch_NoiseWrongP256KeyFailsHandshake(t *testing.T) {
	l := startListener(t, false)

	other, err := GenerateP256StaticKey()
	require.NoError(t, err)
	defer other.Destroy()

	_, err = fetchNoiseFrom(t, l, &NoiseConfig{ServerP256StaticKey: hex.EncodeToString(other.PublicBytes())})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFetch)
	assert.ErrorIs(t, err, truststrap.ErrFetchFailed)
	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, ModeNoise, fe.Mode)
}

// No listener at the address: the connect failure must surface as the fetch
// sentinel, not as a configuration error.
func TestFetch_NoiseP256ConnectFailure(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode: ModeNoise,
		Noise: &NoiseConfig{
			ServerAddr:          "127.0.0.1:1",
			ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
		},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFetch)
	assert.ErrorIs(t, err, truststrap.ErrFetchFailed)
	assert.NotErrorIs(t, err, ErrNoSuite)
}

// A zero PerMethodTimeout and a nil Logger are the facade's defaults; the
// composed client must accept both.
func TestFetch_NoiseDefaultsWithZeroTimeoutAndNilLogger(t *testing.T) {
	l := startListener(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bundle, err := Fetch(ctx, Config{
		Mode:  ModeNoise,
		Noise: &NoiseConfig{ServerAddr: l.addr, ServerP256StaticKey: l.p256Hex},
	})
	require.NoError(t, err)
	requireBundle(t, l, bundle)
}

// =============================================================================
// Fail-closed suite resolution
// =============================================================================

// withSuiteAvailability injects an availability answer for the duration of a
// test, restoring the real probe afterwards.
func withSuiteAvailability(t *testing.T, fn func(suite byte) error) {
	t.Helper()
	prev := ensureSuiteAvailable
	ensureSuiteAvailable = fn
	t.Cleanup(func() { ensureSuiteAvailable = prev })
}

// refuse returns an availability function that refuses the listed suites with
// an ErrSuiteUnavailable chain and defers to the real probe for the rest.
func refuse(suites ...byte) func(byte) error {
	return func(suite byte) error {
		for _, s := range suites {
			if s == suite {
				return &SuiteError{Suite: suite, Cause: ErrSuiteUnavailable}
			}
		}
		return EnsureSuiteAvailable(suite)
	}
}

func TestResolveNoiseClientKeys_NoKeysIsTypedNoSuite(t *testing.T) {
	_, err := resolveNoiseClientKeys(&NoiseConfig{}, discardLogger())
	require.Error(t, err)

	var nse *NoSuiteError
	require.ErrorAs(t, err, &nse)
	assert.ErrorIs(t, err, ErrNoSuite)
	assert.ErrorIs(t, nse.Noise, ErrSuiteKeyMissing)
	assert.ErrorIs(t, nse.P256, ErrSuiteKeyMissing)
	assert.ErrorIs(t, err, ErrSuiteKeyMissing, "Unwrap must expose both reasons")
	assert.Contains(t, err.Error(), "Noise_NK_25519_ChaChaPoly_SHA256")
	assert.Contains(t, err.Error(), "TSBOOT1_P256_AESGCM_SHA256")
}

// Fetch must surface that refusal wrapped in its own FetchError so callers
// classifying on either sentinel work.
func TestFetch_NoiseNoKeysWrapsNoSuite(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:   ModeNoise,
		Noise:  &NoiseConfig{ServerAddr: "127.0.0.1:1"},
		Logger: discardLogger(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFetch)
	assert.ErrorIs(t, err, ErrNoSuite)
	var fe *FetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, ModeNoise, fe.Mode)
}

// The P-256 key is decoded in every build, so its validation is testable
// everywhere: not hex, and the wrong length, are both SuiteError naming the
// suite and carrying ErrSuiteKeyInvalid -- never a fall-through.
func TestResolveNoiseClientKeys_InvalidP256KeyIsTyped(t *testing.T) {
	for name, key := range map[string]string{
		"not hex":      "zz" + strings.Repeat("04", P256PublicKeySize-1),
		"wrong length": strings.Repeat("04", P256PublicKeySize-1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveNoiseClientKeys(&NoiseConfig{
				ServerStaticKey:     placeholderNoiseKey, // a valid fallback must NOT rescue a broken key
				ServerP256StaticKey: key,
			}, discardLogger())
			require.Error(t, err)
			var se *SuiteError
			require.ErrorAs(t, err, &se)
			assert.Equal(t, SuiteP256AESGCM, se.Suite)
			assert.ErrorIs(t, err, ErrSuiteKeyInvalid)
			assert.NotErrorIs(t, err, ErrNoSuite)
		})
	}
}

// The Noise key is decoded only where the build can run Noise; where it
// cannot, the key is skipped without being looked at (see the FIPS file).
func TestResolveNoiseClientKeys_InvalidNoiseKeyIsTypedWhereRunnable(t *testing.T) {
	if !noiseRunnable(t) {
		keys, err := resolveNoiseClientKeys(&NoiseConfig{
			ServerStaticKey:     "not-hex-at-all",
			ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
		}, discardLogger())
		require.NoError(t, err, "an unavailable suite's key must be skipped, not decoded")
		assert.Nil(t, keys.noise)
		assert.NotNil(t, keys.p256)
		return
	}

	_, err := resolveNoiseClientKeys(&NoiseConfig{
		ServerStaticKey:     "not-hex-at-all",
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
	}, discardLogger())
	require.Error(t, err)
	var se *SuiteError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, SuiteNoiseNK, se.Suite)
	assert.ErrorIs(t, err, ErrSuiteKeyInvalid)

	_, err = resolveNoiseClientKeys(&NoiseConfig{ServerStaticKey: "abcd"}, discardLogger())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSuiteKeyInvalid)
	assert.Contains(t, err.Error(), "want 32")
}

// TestResolveNoiseClientKeys_PinnedSuiteIgnoresTheOtherKey pins the contract
// codex found broken on #487: a pinned suite offers exactly that suite, so
// only its key is required and decoded. A stale or malformed key for the
// suite that is NOT pinned must not deny the client -- before this the
// Curve25519 key was decoded before the pin was consulted, so a leftover
// legacy value refused a FIPS client that had pinned the approved suite and
// supplied a valid P-256 point.
func TestResolveNoiseClientKeys_PinnedSuiteIgnoresTheOtherKey(t *testing.T) {
	t.Run("pinned P-256 with a malformed Noise key", func(t *testing.T) {
		keys, err := resolveNoiseClientKeys(&NoiseConfig{
			ServerStaticKey:     "not-hex-at-all",
			ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
			Suite:               SuiteP256AESGCM,
		}, discardLogger())
		require.NoError(t, err, "the unpinned suite's key must not be read")
		assert.Nil(t, keys.noise, "only the pinned suite is offered")
		assert.NotNil(t, keys.p256)
	})

	t.Run("pinned Noise_NK with a malformed P-256 key", func(t *testing.T) {
		cfg := &NoiseConfig{
			ServerStaticKey:     placeholderNoiseKey,
			ServerP256StaticKey: "zz" + strings.Repeat("04", P256PublicKeySize-1),
			Suite:               SuiteNoiseNK,
		}
		if !noiseRunnable(t) {
			// The pin is refused by the build before any key is read; the
			// malformed P-256 key must not be what the error is about.
			_, err := resolveNoiseClientKeys(cfg, discardLogger())
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSuiteUnavailable)
			assert.NotErrorIs(t, err, ErrSuiteKeyInvalid)
			return
		}
		keys, err := resolveNoiseClientKeys(cfg, discardLogger())
		require.NoError(t, err, "the unpinned suite's key must not be read")
		assert.NotNil(t, keys.noise)
		assert.Nil(t, keys.p256, "only the pinned suite is offered")
	})

	t.Run("pinned suite with its own key malformed is still refused", func(t *testing.T) {
		_, err := resolveNoiseClientKeys(&NoiseConfig{
			ServerStaticKey:     placeholderNoiseKey,
			ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize-1),
			Suite:               SuiteP256AESGCM,
		}, discardLogger())
		require.Error(t, err)
		var se *SuiteError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, SuiteP256AESGCM, se.Suite)
		assert.ErrorIs(t, err, ErrSuiteKeyInvalid)
	})
}

func TestResolveNoiseClientKeys_PinnedSuiteWithoutKeyIsTyped(t *testing.T) {
	_, err := resolveNoiseClientKeys(&NoiseConfig{
		ServerStaticKey: placeholderNoiseKey,
		Suite:           SuiteP256AESGCM,
	}, discardLogger())
	require.Error(t, err)
	var se *SuiteError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, SuiteP256AESGCM, se.Suite)
	assert.ErrorIs(t, err, ErrSuiteKeyMissing)

	_, err = resolveNoiseClientKeys(&NoiseConfig{
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
		Suite:               SuiteNoiseNK,
	}, discardLogger())
	require.Error(t, err)
	require.ErrorAs(t, err, &se)
	assert.Equal(t, SuiteNoiseNK, se.Suite)
	// Where Noise cannot run the reason is the build, not the missing key,
	// because no key would help; either way the pinned suite must not be
	// replaced by the configured one.
	if noiseRunnable(t) {
		assert.ErrorIs(t, err, ErrSuiteKeyMissing)
	} else {
		assert.ErrorIs(t, err, ErrSuiteUnavailable)
		assert.NotErrorIs(t, err, ErrSuiteKeyMissing)
	}
}

func TestResolveNoiseClientKeys_UnknownPinnedSuiteIsTyped(t *testing.T) {
	_, err := resolveNoiseClientKeys(&NoiseConfig{
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
		Suite:               0x7f,
	}, discardLogger())
	require.Error(t, err)
	var se *SuiteError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, byte(0x7f), se.Suite)
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
	assert.Contains(t, err.Error(), "0x7f")
}

// The FIPS behaviour, reproduced in any build by injecting the probe's answer:
// Noise unavailable + both keys → Noise skipped, P-256 offered.
func TestResolveNoiseClientKeys_UnavailableSuiteIsSkipped(t *testing.T) {
	withSuiteAvailability(t, refuse(SuiteNoiseNK))

	keys, err := resolveNoiseClientKeys(&NoiseConfig{
		ServerStaticKey:     "not-even-hex", // skipped, so never decoded
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
	}, discardLogger())
	require.NoError(t, err)
	assert.Nil(t, keys.noise, "an unavailable suite must not be offered")
	assert.Len(t, keys.p256, P256PublicKeySize)
}

// Noise unavailable + only a Noise key → typed NoSuiteError carrying the
// build's reason. This is what a FIPS client with a legacy configuration sees.
func TestResolveNoiseClientKeys_UnavailableOnlySuiteIsNoSuite(t *testing.T) {
	withSuiteAvailability(t, refuse(SuiteNoiseNK))

	_, err := resolveNoiseClientKeys(&NoiseConfig{ServerStaticKey: placeholderNoiseKey}, discardLogger())
	require.Error(t, err)
	var nse *NoSuiteError
	require.ErrorAs(t, err, &nse)
	assert.ErrorIs(t, nse.Noise, ErrSuiteUnavailable)
	assert.ErrorIs(t, nse.P256, ErrSuiteKeyMissing)
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
}

// Pinning a suite the build cannot run is refused even when the other suite
// is fully configured: no silent fallback, in either direction.
func TestResolveNoiseClientKeys_PinnedUnavailableSuiteNeverFallsThrough(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse byte
		pin    byte
	}{
		{"pinned Noise, Noise unavailable", SuiteNoiseNK, SuiteNoiseNK},
		{"pinned P-256, P-256 unavailable", SuiteP256AESGCM, SuiteP256AESGCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSuiteAvailability(t, refuse(tc.refuse))

			_, err := resolveNoiseClientKeys(&NoiseConfig{
				ServerStaticKey:     placeholderNoiseKey,
				ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
				Suite:               tc.pin,
			}, discardLogger())
			require.Error(t, err)
			var se *SuiteError
			require.ErrorAs(t, err, &se)
			assert.Equal(t, tc.pin, se.Suite)
			assert.ErrorIs(t, err, ErrSuiteUnavailable)
		})
	}
}

// Both suites refused → NoSuiteError with both reasons from the probe.
func TestResolveNoiseClientKeys_NothingAvailableIsNoSuite(t *testing.T) {
	withSuiteAvailability(t, refuse(SuiteNoiseNK, SuiteP256AESGCM))

	_, err := resolveNoiseClientKeys(&NoiseConfig{
		ServerStaticKey:     placeholderNoiseKey,
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
	}, discardLogger())
	require.Error(t, err)
	var nse *NoSuiteError
	require.ErrorAs(t, err, &nse)
	assert.ErrorIs(t, nse.Noise, ErrSuiteUnavailable)
	assert.ErrorIs(t, nse.P256, ErrSuiteUnavailable)
}

// =============================================================================
// Error types
// =============================================================================

func TestSuiteError_NamesSuiteAndUnwraps(t *testing.T) {
	cause := errors.New("boom")
	err := &SuiteError{Suite: SuiteP256AESGCM, Cause: cause}
	assert.Contains(t, err.Error(), "TSBOOT1_P256_AESGCM_SHA256")
	assert.Contains(t, err.Error(), "boom")
	assert.ErrorIs(t, err, cause)

	unknown := &SuiteError{Suite: 0x42, Cause: cause}
	assert.Contains(t, unknown.Error(), "0x42")
}

func TestNoSuiteError_IsAndUnwrap(t *testing.T) {
	noiseCause, p256Cause := errors.New("noise reason"), errors.New("p256 reason")
	err := &NoSuiteError{Noise: noiseCause, P256: p256Cause}
	assert.ErrorIs(t, err, ErrNoSuite)
	assert.ErrorIs(t, err, noiseCause)
	assert.ErrorIs(t, err, p256Cause)
	assert.NotErrorIs(t, err, ErrFetch)
	assert.Contains(t, err.Error(), "noise reason")
	assert.Contains(t, err.Error(), "p256 reason")
}

func TestBundleCertificateError_IsAndUnwrap(t *testing.T) {
	cause := errors.New("illegal base64")
	err := &BundleCertificateError{Index: 3, Cause: cause}
	assert.ErrorIs(t, err, ErrBundleMalformed)
	assert.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, ErrNoSuite)
	assert.Contains(t, err.Error(), "certificate 3")
}

func TestSuiteName(t *testing.T) {
	assert.Equal(t, "Noise_NK_25519_ChaChaPoly_SHA256", suiteName(SuiteNoiseNK))
	assert.Equal(t, "TSBOOT1_P256_AESGCM_SHA256", suiteName(SuiteP256AESGCM))
	assert.Equal(t, "0x09", suiteName(0x09))
}

// Close is idempotent and safe before any connection was made.
func TestNoiseClient_CloseWithoutConnect(t *testing.T) {
	c, err := newNoiseClient("127.0.0.1:1", &NoiseConfig{
		ServerP256StaticKey: strings.Repeat("04", P256PublicKeySize),
	}, 0, nil)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
}

// A caller's request filters are forwarded, not dropped: the listener
// filters the two-certificate test bundle down to its self-signed root when
// asked for store type "root".
func TestNoiseClient_ForwardsRequestFilters(t *testing.T) {
	l := startListener(t, false)

	c, err := newNoiseClient(l.addr, &NoiseConfig{ServerP256StaticKey: l.p256Hex}, 5*time.Second, discardLogger())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	resp, err := c.FetchCABundle(context.Background(), &truststrap.CABundleRequest{StoreType: "root"})
	require.NoError(t, err)
	assert.Len(t, resp.Certificates, 1, "the store-type filter must reach the listener")
	assert.NotEqual(t, string(l.pem), string(resp.BundlePEM))
}
