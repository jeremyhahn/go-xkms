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

package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// custodyQuietLogger returns a logger that discards output, for tests that
// only care about the returned key/error.
func custodyQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// custodyCapturingLogger returns a logger whose output lands in buf, for
// tests that assert on a specific warning being (or not being) logged.
func custodyCapturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// newCustodyBarrierPair builds two *seal.Barrier instances over the SAME
// in-memory storage backend, unsealed under the same passphrase: b1 as an
// initializing first boot, b2 as a second boot against the surviving data --
// the same shape a real xkmsd restart takes (node/hand-rolled barrier
// construction followed by auto-unseal from the configured passphrase), so a
// key sealed through b1 is exactly what a subsequent process sealing through
// b2 must find.
func newCustodyBarrierPair(t *testing.T) (b1, b2 *seal.Barrier) {
	t.Helper()

	backend := storage.NewMemory()
	cfg := seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}
	logger := custodyQuietLogger()

	b1, err := seal.NewBarrier(logger, backend, cfg, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds1, err := seal.CredentialsFor([]byte("test-system-pw"))
	require.NoError(t, err)
	defer creds1.Secret.Destroy()
	require.NoError(t, b1.Initialize(context.Background(), creds1))

	b2, err = seal.NewBarrier(logger, backend, cfg, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds2, err := seal.CredentialsFor([]byte("test-system-pw"))
	require.NoError(t, err)
	defer creds2.Secret.Destroy()
	require.NoError(t, b2.Unseal(context.Background(), creds2))

	return b1, b2
}

// ============================================================================
// Tests — Noise static key, barrier-sealed custody (go-xkms#35)
// ============================================================================

// TestNoiseKeyCustody_SealedRoundTrip proves the core of go-xkms#35: a key
// sealed by one server construction is the SAME key a later construction
// loads, rather than each boot generating (and thereby invalidating every
// out-of-band-distributed pin) a fresh ephemeral key.
func TestNoiseKeyCustody_SealedRoundTrip(t *testing.T) {
	b1, b2 := newCustodyBarrierPair(t)

	s1 := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b1}
	if !noiseRunnable() {
		requireNoiseRefused(t, s1)
		return
	}

	key1, err := s1.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key1.Destroy()

	s2 := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b2}
	key2, err := s2.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key2.Destroy()

	assert.Equal(t, key1.Public, key2.Public,
		"the second construction must load the key the first one sealed, not generate a new one")
}

// TestNoiseKeyCustody_MigratesLegacyHexAndDeprecates covers the one-time
// migration path: a barrier is configured, nothing is sealed yet, and the
// deprecated bootstrap.noise.static_key_hex config still carries a key. The
// loader must use that key (not generate a different one), seal it, warn
// that the config key is deprecated, and -- on the NEXT boot, exercised here
// via a second Server that does not even have the legacy config set -- load
// it straight from the barrier without touching config again.
func TestNoiseKeyCustody_MigratesLegacyHexAndDeprecates(t *testing.T) {
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	original, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	defer original.Destroy()

	b1, b2 := newCustodyBarrierPair(t)

	var logBuf bytes.Buffer
	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{
				StaticKeyHex: encodeKeyHex(original.Private), //nolint:staticcheck // go-xkms#35: exercises the deprecated migration path
			},
		},
	}
	s1 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf), barrier: b1}

	migrated, err := s1.loadNoiseStaticKey()
	require.NoError(t, err)
	defer migrated.Destroy()
	assert.Equal(t, original.Public, migrated.Public, "the migrated key must be the configured legacy key")
	assert.Contains(t, logBuf.String(), "deprecated", "migrating a legacy key must warn that the config key is deprecated")

	// Second boot: no legacy config at all, different barrier object but the
	// SAME underlying storage -- the sealed key must still be found.
	var logBuf2 bytes.Buffer
	s2 := &Server{config: &config.Config{}, logger: custodyCapturingLogger(&logBuf2), barrier: b2}
	reloaded, err := s2.loadNoiseStaticKey()
	require.NoError(t, err)
	defer reloaded.Destroy()

	assert.Equal(t, original.Public, reloaded.Public, "the sealed key must survive independently of the legacy config")
	assert.NotContains(t, logBuf2.String(), "deprecated", "a key already sealed must not re-trigger the migration warning")
}

// TestNoiseKeyCustody_BarrierGetErrorWraps proves that a barrier failure
// other than "nothing sealed yet" is reported as a typed error rather than
// silently falling through to legacy config or generation, which would mask
// a sealed (or otherwise broken) barrier as first-time setup.
func TestNoiseKeyCustody_BarrierGetErrorWraps(t *testing.T) {
	b1, _ := newCustodyBarrierPair(t)
	require.NoError(t, b1.Seal())

	s := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b1}

	key, err := s.loadNoiseStaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var loadErr *ErrBarrierKeyLoad
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, noiseStaticKeyBarrierKey, loadErr.Key)
	assert.ErrorIs(t, err, seal.ErrSealed)
}

// TestNoiseKeyCustody_NoBarrierPersistsToFileAndReloads covers the no-barrier
// custody floor: with seal disabled but a data directory configured, the
// generated key is persisted to a fixed file (owner-only permissions) rather
// than regenerated every boot, and a second construction against the same
// data directory loads the persisted key instead of generating another one.
func TestNoiseKeyCustody_NoBarrierPersistsToFileAndReloads(t *testing.T) {
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	dataDir := t.TempDir()
	cfg := &config.Config{Storage: config.StorageConfig{Path: dataDir}}

	var logBuf1 bytes.Buffer
	s1 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf1), barrier: nil}
	key1, err := s1.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key1.Destroy()
	assert.Contains(t, logBuf1.String(), "No barrier configured")

	path := filepath.Join(dataDir, noiseStaticKeyFileName)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	var logBuf2 bytes.Buffer
	s2 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf2), barrier: nil}
	key2, err := s2.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key2.Destroy()

	assert.Equal(t, key1.Public, key2.Public, "the second construction must load the persisted key, not generate a new one")
	assert.NotContains(t, logBuf2.String(), "No barrier configured", "a key already persisted must not re-warn on every boot")
}

// TestNoiseKeyCustody_NoBarrierNoDataDirStaysEphemeral locks in the
// pre-existing (and still correct) behavior when there is no barrier AND no
// configured data directory: there is nowhere durable to persist to, so the
// server falls back to an ephemeral key with a warning rather than writing
// to an unpredictable location such as the process's working directory.
func TestNoiseKeyCustody_NoBarrierNoDataDirStaysEphemeral(t *testing.T) {
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	var logBuf bytes.Buffer
	s := &Server{config: &config.Config{}, logger: custodyCapturingLogger(&logBuf)}

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key.Destroy()
	assert.Contains(t, logBuf.String(), "ephemeral")
}

// TestNoiseKeyCustody_ThroughNodeAdoptedBarrier proves custody works through
// the SAME *seal.Barrier the embedded qrdb node hands to xkms at
// pkg/server/qrdb_node.go (node.BarrierRegistry().SystemBarrier()), not just
// the hand-rolled seal.NewBarrier fixture used above -- both produce the
// identical concrete type, but this exercises the real adoption path.
//
// Boot-ordering (Ruling 1: no network service before unseal) is not
// re-tested here -- TestServeSealedWindow_SealedNodeProceedsAfterUnseal in
// sealed_window_test.go already proves initEmbeddedQRDBNode (and so New)
// does not return while the node is sealed, and Start/startNoiseBootstrap
// (which is what calls loadNoiseStaticKey) is only reachable after New has
// returned. This test only adds that the barrier New hands back is one
// loadNoiseStaticKey can actually seal into and reload from.
func TestNoiseKeyCustody_ThroughNodeAdoptedBarrier(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	defer func() { _ = node.Close() }()
	require.False(t, node.IsSealed(), "fixture: node must auto-unseal for this test")

	reg := node.BarrierRegistry()
	require.NotNil(t, reg)
	barrier := reg.SystemBarrier()
	require.NotNil(t, barrier)

	s := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: barrier}
	if !noiseRunnable() {
		requireNoiseRefused(t, s)
		return
	}

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	s2 := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: barrier}
	key2, err := s2.loadNoiseStaticKey()
	require.NoError(t, err)
	defer key2.Destroy()

	assert.Equal(t, key.Public, key2.Public)
}

// ============================================================================
// Tests — P-256 static key, barrier-sealed custody (go-xkms#35, go-xkms#436)
// ============================================================================

// TestP256KeyCustody_SealedRoundTrip is TestNoiseKeyCustody_SealedRoundTrip's
// P-256 counterpart. The approved suite runs in every build, so this test
// carries no noiseRunnable guard.
func TestP256KeyCustody_SealedRoundTrip(t *testing.T) {
	b1, b2 := newCustodyBarrierPair(t)

	s1 := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b1}
	key1, err := s1.loadP256StaticKey()
	require.NoError(t, err)
	defer key1.Destroy()

	s2 := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b2}
	key2, err := s2.loadP256StaticKey()
	require.NoError(t, err)
	defer key2.Destroy()

	assert.Equal(t, key1.PublicBytes(), key2.PublicBytes(),
		"the second construction must load the key the first one sealed, not generate a new one")
}

// TestP256KeyCustody_MigratesLegacyFileAndDeprecates is
// TestNoiseKeyCustody_MigratesLegacyHexAndDeprecates's P-256 counterpart,
// using the file form (P256StaticKeyFile) rather than inline hex to cover
// both legacy input shapes across the two key types.
func TestP256KeyCustody_MigratesLegacyFileAndDeprecates(t *testing.T) {
	original, err := bootstrap.GenerateP256StaticKey()
	require.NoError(t, err)
	defer original.Destroy()

	path := filepath.Join(t.TempDir(), "p256.key")
	require.NoError(t, os.WriteFile(path, []byte(encodeP256Hex(t, original)), 0600))

	b1, b2 := newCustodyBarrierPair(t)

	var logBuf bytes.Buffer
	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{P256StaticKeyFile: path}, //nolint:staticcheck // go-xkms#35: exercises the deprecated migration path
		},
	}
	s1 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf), barrier: b1}

	migrated, err := s1.loadP256StaticKey()
	require.NoError(t, err)
	defer migrated.Destroy()
	assert.Equal(t, original.PublicBytes(), migrated.PublicBytes())
	assert.Contains(t, logBuf.String(), "deprecated")

	var logBuf2 bytes.Buffer
	s2 := &Server{config: &config.Config{}, logger: custodyCapturingLogger(&logBuf2), barrier: b2}
	reloaded, err := s2.loadP256StaticKey()
	require.NoError(t, err)
	defer reloaded.Destroy()

	assert.Equal(t, original.PublicBytes(), reloaded.PublicBytes())
	assert.NotContains(t, logBuf2.String(), "deprecated")
}

// TestP256KeyCustody_BarrierGetErrorWraps is
// TestNoiseKeyCustody_BarrierGetErrorWraps's P-256 counterpart.
func TestP256KeyCustody_BarrierGetErrorWraps(t *testing.T) {
	b1, _ := newCustodyBarrierPair(t)
	require.NoError(t, b1.Seal())

	s := &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: b1}

	key, err := s.loadP256StaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var loadErr *ErrBarrierKeyLoad
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, p256StaticKeyBarrierKey, loadErr.Key)
	assert.ErrorIs(t, err, seal.ErrSealed)
}

// TestP256KeyCustody_NoBarrierPersistsToFileAndReloads is
// TestNoiseKeyCustody_NoBarrierPersistsToFileAndReloads's P-256 counterpart.
func TestP256KeyCustody_NoBarrierPersistsToFileAndReloads(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &config.Config{Storage: config.StorageConfig{Path: dataDir}}

	var logBuf1 bytes.Buffer
	s1 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf1), barrier: nil}
	key1, err := s1.loadP256StaticKey()
	require.NoError(t, err)
	defer key1.Destroy()
	assert.Contains(t, logBuf1.String(), "No barrier configured")

	path := filepath.Join(dataDir, p256StaticKeyFileName)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	var logBuf2 bytes.Buffer
	s2 := &Server{config: cfg, logger: custodyCapturingLogger(&logBuf2), barrier: nil}
	key2, err := s2.loadP256StaticKey()
	require.NoError(t, err)
	defer key2.Destroy()

	assert.Equal(t, key1.PublicBytes(), key2.PublicBytes())
	assert.NotContains(t, logBuf2.String(), "No barrier configured")
}

// TestP256KeyCustody_NoBarrierNoDataDirStaysEphemeral is
// TestNoiseKeyCustody_NoBarrierNoDataDirStaysEphemeral's P-256 counterpart.
func TestP256KeyCustody_NoBarrierNoDataDirStaysEphemeral(t *testing.T) {
	var logBuf bytes.Buffer
	s := &Server{config: &config.Config{}, logger: custodyCapturingLogger(&logBuf)}

	key, err := s.loadP256StaticKey()
	require.NoError(t, err)
	defer key.Destroy()
	assert.Contains(t, logBuf.String(), "ephemeral")
}
