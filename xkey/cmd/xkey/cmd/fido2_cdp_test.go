// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/cdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPKCS8EC generates a P-256 PKCS#8 private key for capture tests.
func newTestPKCS8EC(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return der
}

// recordingBridge captures the credentials passed to SyncCredentials.
type recordingBridge struct {
	creds []cdp.StoredCredential
}

func (r *recordingBridge) SyncCredentials(_ context.Context, creds []cdp.StoredCredential) error {
	r.creds = append(r.creds, creds...)
	return nil
}

func testCDPDevice(storage authenticator.StatefulCredentialStorage) *fido2Device {
	return &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		storage: storage,
	}
}

// --- DURABILITY: credentialAdded -> storage ---

// TestPersistCapturedCredential_RoundTrip asserts a captured CDP credential is
// decoded and persisted into the storage backend with its PKCS#8 key intact.
func TestPersistCapturedCredential_RoundTrip(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.Default(),
		storage: storage,
	}

	pkcs8 := newTestPKCS8EC(t)
	credIDRaw := []byte("cred-cdp-1")
	userRaw := []byte("user-1")

	captured := cdp.StoredCredential{
		CredentialID:         base64.StdEncoding.EncodeToString(credIDRaw),
		IsResidentCredential: true,
		RpID:                 "example.com",
		UserHandle:           base64.StdEncoding.EncodeToString(userRaw),
		SignCount:            0,
	}
	require.NoError(t, captured.SetPrivateKey(base64.StdEncoding.EncodeToString(pkcs8)))

	require.NoError(t, d.persistCapturedCredential(captured))

	loaded, err := storage.Load(credIDRaw)
	require.NoError(t, err)
	assert.Equal(t, "example.com", loaded.RPID)
	assert.Equal(t, userRaw, loaded.UserID)
	assert.Equal(t, pkcs8, loaded.PrivateKeyBytes(), "PKCS#8 key must be persisted verbatim")
	assert.True(t, loaded.Discoverable)
	assert.Equal(t, keybackend.COSEAlgES256, loaded.Algorithm)
	assert.NotEmpty(t, loaded.PublicKeyCOSE, "COSE public key must be derived")
}

// TestPersistCapturedCredential_NoStorage asserts the typed error when storage
// is absent.
func TestPersistCapturedCredential_NoStorage(t *testing.T) {
	d := &fido2Device{cfg: &FIDO2Config{CDPEnabled: true}, logger: slog.Default()}
	cred := cdp.StoredCredential{CredentialID: "x"}
	require.NoError(t, cred.SetPrivateKey("y"))
	err := d.persistCapturedCredential(cred)
	require.ErrorIs(t, err, ErrFIDO2CDPCaptureNoStorage)
}

// TestPersistCapturedCredential_BadBase64 asserts decode failures are typed.
func TestPersistCapturedCredential_BadBase64(t *testing.T) {
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.Default(),
		storage: authenticator.NewMemoryStorage(),
	}
	cred := cdp.StoredCredential{CredentialID: "!!!not-base64!!!"}
	require.NoError(t, cred.SetPrivateKey(base64.StdEncoding.EncodeToString(newTestPKCS8EC(t))))
	err := d.persistCapturedCredential(cred)
	require.ErrorIs(t, err, ErrFIDO2CDPCaptureDecodeFailed)
}

// TestPersistCapturedCredential_BadKey asserts an unparseable PKCS#8 key yields
// the typed decode error.
func TestPersistCapturedCredential_BadKey(t *testing.T) {
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.Default(),
		storage: authenticator.NewMemoryStorage(),
	}
	cred := cdp.StoredCredential{CredentialID: base64.StdEncoding.EncodeToString([]byte("id"))}
	require.NoError(t, cred.SetPrivateKey(base64.StdEncoding.EncodeToString([]byte("not-a-key"))))
	err := d.persistCapturedCredential(cred)
	require.ErrorIs(t, err, ErrFIDO2CDPCaptureDecodeFailed)
}

// TestPersistCapturedCredential_ExistingIsNoop asserts that re-reporting an
// already-stored credential (e.g. on re-sync) is treated as success.
func TestPersistCapturedCredential_ExistingIsNoop(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.Default(),
		storage: storage,
	}

	captured := cdp.StoredCredential{
		CredentialID: base64.StdEncoding.EncodeToString([]byte("dup")),
		RpID:         "example.com",
	}
	require.NoError(t, captured.SetPrivateKey(base64.StdEncoding.EncodeToString(newTestPKCS8EC(t))))
	require.NoError(t, d.persistCapturedCredential(captured))
	require.NoError(t, d.persistCapturedCredential(captured), "duplicate capture must be a no-op")
}

// TestDeriveCOSEFromPKCS8_ES256 asserts COSE derivation for a P-256 key.
func TestDeriveCOSEFromPKCS8_ES256(t *testing.T) {
	alg, cose, err := deriveCOSEFromPKCS8(newTestPKCS8EC(t))
	require.NoError(t, err)
	assert.Equal(t, keybackend.COSEAlgES256, alg)
	assert.NotEmpty(t, cose)
}

// TestDeriveCOSEFromPKCS8_Invalid asserts a parse error for garbage input.
func TestDeriveCOSEFromPKCS8_Invalid(t *testing.T) {
	_, _, err := deriveCOSEFromPKCS8([]byte("garbage"))
	require.ErrorIs(t, err, ErrFIDO2CDPCaptureKeyParseFailed)
}

// --- DURABILITY: startup sync sources the captured key from storage ---

// TestSyncCredentialsToCDP_UsesStoredKey asserts that a credential persisted
// with an inline PrivateKey (the CDP-capture case) is included in the startup
// re-sync to Chrome WITHOUT requiring the key backend to export it. This proves
// round-trip: a credential captured in session 1 is re-synced in session 2.
func TestSyncCredentialsToCDP_UsesStoredKey(t *testing.T) {
	storage := authenticator.NewMemoryStorage()

	pkcs8 := newTestPKCS8EC(t)
	credID := []byte("captured-cred")
	storedCred := &authenticator.StoredCredential{
		CredentialID: credID,
		RPID:         "example.com",
		Algorithm:    keybackend.COSEAlgES256,
		Discoverable: true,
	}
	require.NoError(t, storedCred.SetPrivateKey(append([]byte(nil), pkcs8...)))
	require.NoError(t, storage.Store(storedCred))

	rec := &recordingBridge{}
	d := &fido2Device{
		cfg:    &FIDO2Config{CDPEnabled: true},
		logger: slog.Default(),
		// No keyBackend: forces the sync to use the stored inline key. The
		// stored-key branch must be taken for the credential to be synced.
		storage: storage,
	}

	d.syncCredentialsToCDPVia(context.Background(), rec)

	require.Len(t, rec.creds, 1)
	assert.Equal(t, base64.StdEncoding.EncodeToString(credID), rec.creds[0].CredentialID)
	assert.Equal(t, base64.StdEncoding.EncodeToString(pkcs8), rec.creds[0].PrivateKeyString())
	assert.Equal(t, "example.com", rec.creds[0].RpID)
}

// TestPersistCapturedCredential_StandardBase64WithSlash is the regression test
// for the CDP base64 bug: a credentialAdded event whose binary fields are
// standard base64 (containing '/' and '+', with padding) must decode and
// persist. The credentialId is the real one observed live from Chrome's CDP
// virtual authenticator, which contains a '/' at byte 4.
func TestPersistCapturedCredential_StandardBase64WithSlash(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		storage: storage,
	}

	// Real credentialId from a live CDP registration; std base64, has a '/'.
	const realCredID = "T4Gj/BomswwcvyYxNjfPwegYkwc8qWQoFAnulkkI1HE="
	credIDRaw, err := base64.StdEncoding.DecodeString(realCredID)
	require.NoError(t, err)
	require.Contains(t, realCredID, "/", "fixture must exercise the std-base64 '/' byte")

	pkcs8 := newTestPKCS8EC(t)
	// A user handle that also contains both '+' and '/' once encoded.
	userRaw := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB}
	userEnc := base64.StdEncoding.EncodeToString(userRaw)
	require.True(t, hasStdBase64Special(userEnc), "user handle fixture must contain '+' or '/'")

	captured := cdp.StoredCredential{
		CredentialID:         realCredID,
		IsResidentCredential: true,
		RpID:                 "localhost",
		UserHandle:           userEnc,
		SignCount:            0,
	}
	require.NoError(t, captured.SetPrivateKey(base64.StdEncoding.EncodeToString(pkcs8)))

	require.NoError(t, d.persistCapturedCredential(captured),
		"standard base64 credentialId containing '/' must decode and persist")

	loaded, err := storage.Load(credIDRaw)
	require.NoError(t, err)
	assert.Equal(t, credIDRaw, loaded.CredentialID)
	assert.Equal(t, "localhost", loaded.RPID)
	assert.Equal(t, userRaw, loaded.UserID)
	assert.Equal(t, pkcs8, loaded.PrivateKeyBytes(), "PKCS#8 key must be persisted verbatim")
	assert.Equal(t, keybackend.COSEAlgES256, loaded.Algorithm)
}

// hasStdBase64Special reports whether s contains a character unique to the
// standard base64 alphabet ('+' or '/'), proving the fixture would break a
// base64url decoder.
func hasStdBase64Special(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '+' || s[i] == '/' {
			return true
		}
	}
	return false
}

// TestCDPCredential_StdBase64RoundTrip proves end-to-end durability: a
// credential captured from CDP (standard base64 in) is persisted, and the
// startup re-sync emits the SAME bytes re-encoded as standard base64 that
// Chrome's WebAuthn.addCredential expects.
func TestCDPCredential_StdBase64RoundTrip(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	d := &fido2Device{
		cfg:     &FIDO2Config{CDPEnabled: true},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		storage: storage,
	}

	const realCredID = "T4Gj/BomswwcvyYxNjfPwegYkwc8qWQoFAnulkkI1HE="
	credIDRaw, err := base64.StdEncoding.DecodeString(realCredID)
	require.NoError(t, err)

	pkcs8 := newTestPKCS8EC(t)
	pkEnc := base64.StdEncoding.EncodeToString(pkcs8)

	// Inbound: capture exactly what CDP delivers (standard base64).
	inbound := cdp.StoredCredential{
		CredentialID:         realCredID,
		IsResidentCredential: true,
		RpID:                 "localhost",
	}
	require.NoError(t, inbound.SetPrivateKey(pkEnc))
	require.NoError(t, d.persistCapturedCredential(inbound))

	// Outbound: re-sync to a (recording) Chrome virtual authenticator.
	rec := &recordingBridge{}
	d.syncCredentialsToCDPVia(context.Background(), rec)

	require.Len(t, rec.creds, 1)
	// The re-emitted fields must be standard base64 and byte-identical to the
	// values Chrome originally sent, so addCredential restores the credential.
	assert.Equal(t, realCredID, rec.creds[0].CredentialID,
		"sync-out credentialId must match the std-base64 CDP sent")
	assert.Equal(t, pkEnc, rec.creds[0].PrivateKeyString(),
		"sync-out privateKey must be std-base64 of the verbatim PKCS#8")

	// And decoding the re-emitted value yields the original raw bytes.
	gotID, err := base64.StdEncoding.DecodeString(rec.creds[0].CredentialID)
	require.NoError(t, err)
	assert.Equal(t, credIDRaw, gotID)
}

// --- DETERMINISM: UHID suppressed in CDP mode ---

// TestRun_CDPMode_SkipsUHID asserts that in --cdp mode Run never opens a UHID
// device. The context is cancelled immediately; cdpLoop returns and uhidDevice
// remains nil (no virtual USB authenticator was created).
func TestRun_CDPMode_SkipsUHID(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	d := testCDPDevice(storage)
	// Point the IPC socket at a temp dir so the test never touches the host's
	// default socket path; CDP host/port point at a closed port so NewClient
	// fails fast and Run falls through to cdpLoop.
	d.cfg.SocketPath = t.TempDir() + "/xkey-test.sock"
	d.cfg.CDPHost = "127.0.0.1"
	d.cfg.CDPPort = 1 // unused/closed port: NewClient fails, logged, continues

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := d.Run(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, d.uhidDevice, "UHID device must not be created in CDP mode")
}

// TestCDPLoop_ReturnsOnCancel asserts the CDP loop exits with the context error.
func TestCDPLoop_ReturnsOnCancel(t *testing.T) {
	d := testCDPDevice(authenticator.NewMemoryStorage())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.cdpLoop(ctx)
	assert.True(t, errors.Is(err, context.Canceled))
}
