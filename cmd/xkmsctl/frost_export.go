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

//go:build frost

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// frostRecipientKeyCN names the ECDSA P-256 key a participant's dealer
// packages are encrypted to (go-xkms#1337). It lives in the participant's
// <key-dir>/frost/secrets beside the share wrapping key, as encrypted PKCS#8
// under the same FROST passphrase, and never leaves that directory: only its
// public half is given to the dealer.
const frostRecipientKeyCN = "frost-share-recipient"

// frostPackageKeyAlgorithm and frostPackageContentAlgorithm are the JWE
// (RFC 7516/7518) algorithms a dealer package is encrypted with: an
// ephemeral-static ECDH-ES key agreement to the recipient's P-256 key, the
// derived key wrapping a random AES_256_CBC_HMAC_SHA_512 content key (RFC 7518
// §5.2.5). The JWE protected header, which names the recipient key, is
// authenticated by the HMAC tag. The content algorithm is CBC-HMAC rather than
// A256GCM because the JWE library seals GCM under an IV it draws itself, an
// arbitrary-IV construction GODEBUG=fips140=only refuses; AES-CBC and
// HMAC-SHA-512 are both approved, so a dealer package is sealed in either mode.
const (
	frostPackageKeyAlgorithm     = "ECDH-ES+A256KW"
	frostPackageContentAlgorithm = "A256CBC-HS512"
)

// EncryptedKeyPackageExport is the file dealer keygen writes for each
// participant. The key package itself -- secret share, group public key and
// verification shares -- is the JWE in Package, encrypted to the
// participant's recipient key. KeyID, ParticipantID and ParticipantName are
// unauthenticated routing labels for the operator: import reads every value
// it stores from the decrypted package, never from them.
type EncryptedKeyPackageExport struct {
	KeyID           string `json:"key_id"`
	ParticipantID   uint32 `json:"participant_id"`
	ParticipantName string `json:"participant_name,omitempty"`
	Package         string `json:"package"` // JWE compact serialization of a KeyPackageExport
}

// frostRecipientKeyAttributes returns the attributes of the recipient key,
// carrying passphrase so the PKCS#8 backend stores it encrypted (PBES2) and
// decrypts it on use.
func frostRecipientKeyAttributes(passphrase client.Password) *client.KeyAttributes {
	return &client.KeyAttributes{
		CN:            frostRecipientKeyCN,
		KeyType:       client.KeyTypeEncryption,
		StoreType:     client.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &client.ECCAttributes{Curve: elliptic.P256()},
		Password:      passphrase,
	}
}

// ensureFrostRecipientKey returns the public half of the store's recipient
// key, generating the key on first use and reusing it thereafter.
func ensureFrostRecipientKey(ctx context.Context, store *frostLocalStore) (*ecdsa.PublicKey, error) {
	attrs := frostRecipientKeyAttributes(store.passphrase)
	if err := client.EnsurePrivateSealKey(ctx, store.provider, attrs); err != nil {
		return nil, frostRecipientKeyError(err)
	}
	key, err := loadFrostRecipientKey(ctx, store)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

// loadFrostRecipientKey decrypts and returns the store's recipient key. It
// never creates one: a store without a recipient key is reported as
// ErrFrostRecipientKeyMissing.
func loadFrostRecipientKey(ctx context.Context, store *frostLocalStore) (*ecdsa.PrivateKey, error) {
	key, err := store.provider.GetKey(ctx, frostRecipientKeyAttributes(store.passphrase))
	if err != nil {
		if errors.Is(err, client.ErrBackendKeyNotFound) {
			return nil, ErrFrostRecipientKeyMissing
		}
		return nil, frostRecipientKeyError(err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &WrappedDetailError{Sentinel: ErrProvisionFrostRecipientKeyFailed, Detail: "stored recipient key is not an ECDSA key"}
	}
	return ecKey, nil
}

// frostRecipientKeyError classifies a failure to generate or read the
// recipient key: a key that does not decrypt under the passphrase is
// ErrFrostPassphraseRejected, as for the share wrapping key.
func frostRecipientKeyError(err error) error {
	if errors.Is(err, client.ErrPKCS8KeyDecodingFailed) {
		return &WrappedError{Sentinel: ErrFrostPassphraseRejected, Err: err}
	}
	return &WrappedError{Sentinel: ErrProvisionFrostRecipientKeyFailed, Err: err}
}

// frostRecipientID returns the RFC 7638 SHA-256 JWK thumbprint of a recipient
// public key. It is the JWE "kid" of every package encrypted to the key, and
// what `frost recipient` prints so a participant can confirm with the dealer,
// out of band, that the dealer holds the right key.
func frostRecipientID(publicKey *ecdsa.PublicKey) (string, error) {
	return client.JWKThumbprintSHA256(publicKey)
}

// readFrostRecipientPublicKey reads a PEM-encoded ECDSA P-256 public key --
// the file `frost recipient --public-key-file` writes -- from path.
func readFrostRecipientPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientKeyInvalid, Detail: path, Err: err}
	}
	publicKey, err := client.DecodePublicKeyPEM(data)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientKeyInvalid, Detail: path, Err: err}
	}
	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientKeyInvalid, Detail: path}
	}
	return ecKey, nil
}

// parseFrostRecipients resolves dealer keygen's --recipient values, each
// <participant-id>=<public-key-file>, into one recipient public key per
// participant 1..total. Every participant must have exactly one, and no two
// participants may share a key.
func parseFrostRecipients(specs []string, total int) (map[uint32]*ecdsa.PublicKey, error) {
	recipients := make(map[uint32]*ecdsa.PublicKey, len(specs))
	holders := make(map[string]uint32, len(specs))

	for _, spec := range specs {
		idText, path, found := strings.Cut(spec, "=")
		id, err := strconv.ParseUint(strings.TrimSpace(idText), 10, 32)
		if !found || path == "" || err != nil || id < 1 || id > uint64(total) {
			return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientSpecInvalid, Detail: spec}
		}
		participantID := uint32(id)
		if _, seen := recipients[participantID]; seen {
			return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientDuplicate, Detail: strconv.FormatUint(id, 10)}
		}

		publicKey, err := readFrostRecipientPublicKey(path)
		if err != nil {
			return nil, err
		}
		recipientID, err := frostRecipientID(publicKey)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrFrostRecipientKeyInvalid, Detail: path, Err: err}
		}
		if other, reused := holders[recipientID]; reused {
			return nil, &WrappedDetailError{
				Sentinel: ErrFrostRecipientReused,
				Detail:   "participants " + strconv.FormatUint(uint64(other), 10) + " and " + strconv.FormatUint(id, 10),
			}
		}
		holders[recipientID] = participantID
		recipients[participantID] = publicKey
	}

	for id := uint32(1); id <= uint32(total); id++ {
		if _, ok := recipients[id]; !ok {
			return nil, &FrostRecipientMissingError{ID: id}
		}
	}
	return recipients, nil
}

// encryptKeyPackageExport encrypts export to recipient, returning the file
// dealer keygen writes. The JWE's "kid" is the recipient key's thumbprint,
// which import checks before decrypting.
func encryptKeyPackageExport(export *KeyPackageExport, recipient *ecdsa.PublicKey) (*EncryptedKeyPackageExport, error) {
	recipientID, err := frostRecipientID(recipient)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrEncryptPackageFailed, Err: err}
	}
	plaintext, err := json.Marshal(export)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrMarshalPackageFailed, Err: err}
	}
	defer secure.Wipe(plaintext)

	encrypter, err := client.NewJWEEncrypter(frostPackageKeyAlgorithm, frostPackageContentAlgorithm, recipient)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrEncryptPackageFailed, Err: err}
	}
	jwe, err := encrypter.EncryptWithHeader(plaintext, map[string]interface{}{"kid": recipientID})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrEncryptPackageFailed, Err: err}
	}

	return &EncryptedKeyPackageExport{
		KeyID:           export.KeyID,
		ParticipantID:   export.ParticipantID,
		ParticipantName: export.ParticipantName,
		Package:         jwe,
	}, nil
}

// decryptKeyPackageExport decrypts an encrypted dealer package with the
// participant's recipient key. It refuses a package with no JWE
// (ErrFrostPackageNotEncrypted), one encrypted to another recipient key
// (ErrFrostPackageRecipientMismatch), and one that fails authenticated
// decryption (ErrFrostPackageDecryptFailed).
func decryptKeyPackageExport(encrypted *EncryptedKeyPackageExport, recipientKey *ecdsa.PrivateKey) (*KeyPackageExport, error) {
	if encrypted.Package == "" {
		return nil, ErrFrostPackageNotEncrypted
	}

	recipientID, err := frostRecipientID(&recipientKey.PublicKey)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrFrostPackageDecryptFailed, Err: err}
	}
	kid, err := client.ExtractJWEKID(encrypted.Package)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrFrostPackageDecryptFailed, Err: err}
	}
	if kid != recipientID {
		return nil, &WrappedDetailError{
			Sentinel: ErrFrostPackageRecipientMismatch,
			Detail:   "package recipient " + kid + ", this key directory's recipient " + recipientID,
		}
	}

	plaintext, err := client.NewJWEDecrypter().Decrypt(encrypted.Package, recipientKey)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrFrostPackageDecryptFailed, Err: err}
	}
	defer secure.Wipe(plaintext)

	var export KeyPackageExport
	if err := json.Unmarshal(plaintext, &export); err != nil {
		return nil, &WrappedError{Sentinel: ErrParsePackageFileFailed, Err: err}
	}
	return &export, nil
}
