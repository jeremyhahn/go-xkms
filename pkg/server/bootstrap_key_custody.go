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
	"errors"
	"os"
	"path/filepath"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Custody for the bootstrap listener's two static keys (go-xkms#35).
//
// Ruling 2 on go-xkms#35 settles custody: the key is persisted, and the
// barrier is the at-rest protection when one is configured. The barrier is
// already in hand before Server.Start ever runs (adopted from the qrdb node
// at construction, pkg/server/qrdb_node.go -- the only barrier there is),
// so loadBootstrapKeys — called from the post-unseal startNoiseBootstrap
// goroutine — always sees a live, unsealed s.barrier when one is configured.
// Ruling 1 (no network service before unseal) therefore already holds for
// this listener by construction; there is nothing to sequence here.
//
// Storage reuses the barrier's OWN key-value store rather than a new path
// scheme: *seal.Barrier (qrdbsdk.StorageBarrier) exposes Put/Get, which
// encrypt under the barrier's master key and persist through its configured
// storage backend -- exactly the mechanism pkg/server/credentials/service.go
// already uses to seal operator-owned credentials (credentialPrefix). The
// bootstrap static keys are namespaced the same way, under
// bootstrapKeyBarrierPrefix, so an operator inspecting sealed state finds
// both kinds of secret in the one place.
//
// Without a barrier, the key still must not be ephemeral: it is persisted in
// the same plaintext hex form the deprecated config keys always accepted,
// at a fixed path inside the server's own data directory, written atomically
// (temp file + rename) with owner-only permissions -- the same shape
// go-truststrap's CLI and go-qrdb's cluster-enrollment advertiser already use
// for a Noise key with no barrier available to them. The operator is warned
// once; the server never refuses to start over this.
const (
	// bootstrapKeyBarrierPrefix namespaces the sealed bootstrap static keys
	// within the barrier's key-value store, mirroring credentialPrefix in
	// pkg/server/credentials/service.go.
	bootstrapKeyBarrierPrefix = "bootstrap-noise/"

	// noiseStaticKeyBarrierKey is the barrier key holding the hex-encoded
	// Noise_NK (X25519) static private key.
	noiseStaticKeyBarrierKey = bootstrapKeyBarrierPrefix + "x25519-static-key"

	// p256StaticKeyBarrierKey is the barrier key holding the hex-encoded
	// TSBOOT1_P256_AESGCM_SHA256 (P-256) static private key.
	p256StaticKeyBarrierKey = bootstrapKeyBarrierPrefix + "p256-static-key"
)

const (
	// noiseStaticKeyFileName is the fixed file, inside the server's data
	// directory, that holds the plaintext hex Noise static key when no
	// barrier is configured to seal it.
	noiseStaticKeyFileName = "bootstrap-noise-x25519.key"

	// p256StaticKeyFileName is the P-256 equivalent of noiseStaticKeyFileName.
	p256StaticKeyFileName = "bootstrap-noise-p256.key"
)

// loadNoiseStaticKey resolves the Noise_NK static key: barrier-sealed
// storage when a barrier is configured, a persisted plaintext file otherwise.
// See the package-level custody note above. The returned key holds its
// private scalar in protected memory; the caller owns it and must Destroy it
// once the bootstrap server that uses it has stopped.
func (s *Server) loadNoiseStaticKey() (*noiseproto.StaticKey, error) {
	if s.barrier != nil {
		return s.loadOrSealNoiseStaticKey()
	}
	return s.loadOrPersistNoiseStaticKeyFile()
}

// loadP256StaticKey resolves the P-256 static key for the FIPS-approved
// suite, mirroring loadNoiseStaticKey. The returned key holds its private
// scalar in protected memory; the caller owns it and must Destroy it once the
// bootstrap server that uses it has stopped.
func (s *Server) loadP256StaticKey() (*bootstrap.P256StaticKey, error) {
	if s.barrier != nil {
		return s.loadOrSealP256StaticKey()
	}
	return s.loadOrPersistP256StaticKeyFile()
}

// ---------------------------------------------------------------------------
// Barrier-sealed custody
// ---------------------------------------------------------------------------

// loadOrSealNoiseStaticKey implements the barrier-present boot order: load
// the sealed key if one exists; otherwise generate a fresh key and seal it.
// Every path after the first leaves a sealed key in the barrier so the next
// start takes the first branch.
func (s *Server) loadOrSealNoiseStaticKey() (*noiseproto.StaticKey, error) {
	key, err := s.loadSealedNoiseStaticKey()
	switch {
	case err == nil:
		return key, nil
	case isBarrierKeyNotFound(err):
		// Not sealed yet -- fall through to generation.
	default:
		return nil, &ErrBarrierKeyLoad{Key: noiseStaticKeyBarrierKey, Err: err}
	}

	key, err = noiseproto.GenerateStaticKey()
	if err != nil {
		return nil, err
	}
	if err := s.sealNoiseStaticKey(key); err != nil {
		key.Destroy()
		return nil, err
	}
	return key, nil
}

// loadOrSealP256StaticKey is loadOrSealNoiseStaticKey's P-256 counterpart.
func (s *Server) loadOrSealP256StaticKey() (*bootstrap.P256StaticKey, error) {
	key, err := s.loadSealedP256StaticKey()
	switch {
	case err == nil:
		return key, nil
	case isBarrierKeyNotFound(err):
		// Not sealed yet -- fall through to generation.
	default:
		return nil, &ErrBarrierKeyLoad{Key: p256StaticKeyBarrierKey, Err: err}
	}

	key, err = bootstrap.GenerateP256StaticKey()
	if err != nil {
		return nil, err
	}
	if err := s.sealP256StaticKey(key); err != nil {
		key.Destroy()
		return nil, err
	}
	return key, nil
}

// isBarrierKeyNotFound reports whether err is a barrier Get miss -- "nothing
// sealed under this key yet" -- as opposed to a real failure (sealed barrier,
// corrupt ciphertext, storage error). The barrier's Get returns whichever
// sentinel its underlying storage backend uses for a missing key: xkms's own
// backends (and so a seal.NewBarrier test fixture over them) report
// storage.ErrNotFound, while a barrier adopted from the embedded qrdb
// node -- the SAME *seal.Barrier type, over go-qrdb's own Pebble backend --
// reports seal.ErrSecretNotFound (see pkg/seal/barrier_adapter.go's
// tenantMetadataStore for the same discrepancy on the tenant-lookup path).
// Both are "not found" here.
func isBarrierKeyNotFound(err error) bool {
	return errors.Is(err, storage.ErrNotFound) || errors.Is(err, seal.ErrSecretNotFound)
}

// loadSealedNoiseStaticKey reads the hex-encoded Noise static key from the
// barrier's key-value store and decodes it. Returns a "not found" error
// (see isBarrierKeyNotFound) when no key has been sealed yet.
func (s *Server) loadSealedNoiseStaticKey() (*noiseproto.StaticKey, error) {
	hexKey, err := s.barrier.Get(context.Background(), noiseStaticKeyBarrierKey)
	if err != nil {
		return nil, err
	}
	defer noiseproto.WipeBytes(hexKey)
	return noiseproto.DecodeStaticKey(hexKey)
}

// encodeNoiseStaticKeyHex hex-encodes key's private scalar into a []byte the
// caller owns and must wipe with secure.Wipe on every path. It is the Noise
// counterpart of bootstrap_suite.go's encodeP256StaticKeyHex: the barrier and
// the key file both take a []byte, so the hex form is on the heap for exactly
// as long as the caller holds this slice.
//
// Keeping the hex in a secure.Buffer across the barrier's Put instead needs a
// borrow around Put (a Buffer has no read outside one), and Put encrypts through
// protected memory of its own, which pkg/secure does not allow inside a
// borrow. A barrier Put that takes a Borrower would close it; that is a
// go-qrdb API.
func encodeNoiseStaticKeyHex(key *noiseproto.StaticKey) ([]byte, error) {
	hexKey := make([]byte, noiseproto.HexKeySize)
	if err := noiseproto.EncodeStaticKey(hexKey, key); err != nil {
		secure.Wipe(hexKey)
		return nil, err
	}
	return hexKey, nil
}

// sealNoiseStaticKey hex-encodes key's private scalar and persists it in the
// barrier under noiseStaticKeyBarrierKey. key is the caller's;
// sealNoiseStaticKey neither mutates nor destroys it.
func (s *Server) sealNoiseStaticKey(key *noiseproto.StaticKey) error {
	hexKey, err := encodeNoiseStaticKeyHex(key)
	if err != nil {
		return &ErrBarrierKeySeal{Key: noiseStaticKeyBarrierKey, Err: err}
	}
	defer secure.Wipe(hexKey)

	if err := s.barrier.Put(context.Background(), noiseStaticKeyBarrierKey, hexKey); err != nil {
		return &ErrBarrierKeySeal{Key: noiseStaticKeyBarrierKey, Err: err}
	}
	return nil
}

// loadSealedP256StaticKey is loadSealedNoiseStaticKey's P-256 counterpart.
func (s *Server) loadSealedP256StaticKey() (*bootstrap.P256StaticKey, error) {
	hexKey, err := s.barrier.Get(context.Background(), p256StaticKeyBarrierKey)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(hexKey)
	return decodeP256StaticKey(hexKey)
}

// sealP256StaticKey is sealNoiseStaticKey's P-256 counterpart. It delegates
// the encode step to bootstrap_suite.go's encodeP256StaticKeyHex, which owns
// the locked enclave go-truststrap's P-256 encoder writes into; everything
// here works with the []byte that helper hands back.
func (s *Server) sealP256StaticKey(key *bootstrap.P256StaticKey) error {
	hexKey, err := encodeP256StaticKeyHex(key)
	if err != nil {
		return &ErrBarrierKeySeal{Key: p256StaticKeyBarrierKey, Err: err}
	}
	defer secure.Wipe(hexKey)

	if err := s.barrier.Put(context.Background(), p256StaticKeyBarrierKey, hexKey); err != nil {
		return &ErrBarrierKeySeal{Key: p256StaticKeyBarrierKey, Err: err}
	}
	return nil
}

// ---------------------------------------------------------------------------
// No-barrier custody: persisted plaintext file
// ---------------------------------------------------------------------------

// loadOrPersistNoiseStaticKeyFile implements the no-barrier boot order: a key
// persisted at a fixed path inside the data directory is loaded, or generated
// and persisted there with a one-time warning. With no data directory
// configured, there is nowhere durable to persist to, so the server falls
// back to an ephemeral-with-warning key rather than writing to an
// unpredictable location.
func (s *Server) loadOrPersistNoiseStaticKeyFile() (*noiseproto.StaticKey, error) {
	dataDir := s.config.Datastore.Path
	if dataDir == "" {
		s.logger.Warn("No Noise static key configured and no barrier or data directory available; " +
			"generating an ephemeral key. This is NOT recommended for production.")
		return noiseproto.GenerateStaticKey()
	}

	path := filepath.Join(dataDir, noiseStaticKeyFileName)
	if data, err := readHexKeyFile(path); err == nil {
		defer noiseproto.WipeBytes(data)
		return noiseproto.DecodeStaticKey(data)
	} else if !os.IsNotExist(err) {
		return nil, &ErrFileRead{Path: path, Err: err}
	}

	key, err := noiseproto.GenerateStaticKey()
	if err != nil {
		return nil, err
	}

	hexKey, err := encodeNoiseStaticKeyHex(key)
	if err != nil {
		key.Destroy()
		return nil, err
	}
	defer secure.Wipe(hexKey)
	if err := writeHexKeyFileAtomic(path, hexKey); err != nil {
		key.Destroy()
		return nil, &ErrFileWrite{Path: path, Err: err}
	}

	s.logger.Warn("No barrier configured: the Noise static key is persisted in plaintext at " +
		path + ". Configure a barrier for at-rest protection.")
	return key, nil
}

// loadOrPersistP256StaticKeyFile is loadOrPersistNoiseStaticKeyFile's P-256
// counterpart.
func (s *Server) loadOrPersistP256StaticKeyFile() (*bootstrap.P256StaticKey, error) {
	dataDir := s.config.Datastore.Path
	if dataDir == "" {
		s.logger.Warn("No P-256 bootstrap static key configured and no barrier or data directory " +
			"available; generating an ephemeral key. This is NOT recommended for production.")
		return bootstrap.GenerateP256StaticKey()
	}

	path := filepath.Join(dataDir, p256StaticKeyFileName)
	if data, err := readHexKeyFile(path); err == nil {
		defer secure.Wipe(data)
		return decodeP256StaticKey(data)
	} else if !os.IsNotExist(err) {
		return nil, &ErrFileRead{Path: path, Err: err}
	}

	key, err := bootstrap.GenerateP256StaticKey()
	if err != nil {
		return nil, err
	}

	hexKey, err := encodeP256StaticKeyHex(key)
	if err != nil {
		key.Destroy()
		return nil, err
	}
	defer secure.Wipe(hexKey)
	if err := writeHexKeyFileAtomic(path, hexKey); err != nil {
		key.Destroy()
		return nil, &ErrFileWrite{Path: path, Err: err}
	}

	s.logger.Warn("No barrier configured: the P-256 bootstrap static key is persisted in " +
		"plaintext at " + path + ". Configure a barrier for at-rest protection.")
	return key, nil
}

// readHexKeyFile reads and trims a hex-encoded key file. A missing file is
// reported as os.ErrNotExist (checked with os.IsNotExist or errors.Is), which
// callers treat as "generate and persist" rather than a failure.
func readHexKeyFile(path string) ([]byte, error) {
	// #nosec G304 - path is built from the server's own configured data directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(data), nil
}

// writeHexKeyFileAtomic writes hexKey to path with owner-only permissions,
// atomically (temp file, then rename) so a crash mid-write cannot leave a
// truncated file that the next boot would misread as a corrupt key. This is
// the same load-or-generate shape go-truststrap's CLI and go-qrdb's
// cluster-enrollment advertiser already use for a plaintext Noise key file.
func writeHexKeyFileAtomic(path string, hexKey []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	return fsutil.WriteFileAtomic(path, hexKey, 0600)
}
