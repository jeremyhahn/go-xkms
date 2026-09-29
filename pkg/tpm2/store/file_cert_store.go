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

package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FileCertStore implements CertificateStorer using storage.Backend -- the
// same abstraction FileBackend persists TPM key blobs with. A certificate
// therefore lives beside the object's key material under the storage a
// caller already rooted at the device's key directory (see
// NewStorageFactory), rather than in a separate cert-only store: there is
// exactly one place on disk a device's TPM state lives.
//
// This is what gives a hardware device the persistent certificate store the
// in-process TPM simulator's development-only MemoryCertStore does not need
// (a fresh throwaway IAK certificate is re-minted every time the simulator
// opens): a hardware TPM's IAK certificate is issued once, by enroll-01, and
// must still be there when a later, separate process runs device-attest-01
// (go-xkms#1100).
type FileCertStore struct {
	logger  *slog.Logger
	storage storage.Backend
}

// NewFileCertStore creates a certificate store backed by storage.Backend.
// For convenience, use NewStorageFactory to create a complete storage setup
// that shares its backend between key blobs and certificates.
func NewFileCertStore(logger *slog.Logger, backend storage.Backend) CertificateStorer {
	return &FileCertStore{
		logger:  logger,
		storage: backend,
	}
}

// certStorageKey composes the storage key for a certificate: the Common
// Name, optionally parent-prefixed (mirroring MemoryCertStore's addressing
// so the two stores name the same certificate identically), plus
// FSEXT_CERTIFICATE. An empty CN is refused for the same reason storageKey
// refuses one for key blobs: "" plus the extension is a valid-looking key
// every nameless certificate would share.
func certStorageKey(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil || attrs.CN == "" {
		return "", ErrEmptyKeyCN
	}
	key := attrs.CN
	if attrs.Parent != nil && attrs.Parent.CN != "" {
		key = fmt.Sprintf("%s/%s", attrs.Parent.CN, attrs.CN)
	}
	return key + FSEXT_CERTIFICATE, nil
}

// Get retrieves a certificate from storage.
func (f *FileCertStore) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	key, err := certStorageKey(attrs)
	if err != nil {
		return nil, err
	}

	data, err := f.storage.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCertNotFound
		}
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to read certificate %s", key), Err: err}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &errs.Detail{Err: ErrInvalidPublicKey, Detail: fmt.Sprintf("certificate %s: failed to decode PEM block", key)}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to parse certificate %s", key), Err: err}
	}

	if f.logger != nil {
		f.logger.Debug("certificate retrieved from file store", slog.String("key", key))
	}

	return cert, nil
}

// Save writes a certificate to storage, PEM-encoded, overwriting any
// certificate already stored under attrs -- a device re-enrolling replaces
// its previous certificate, it does not accumulate one per enrollment.
func (f *FileCertStore) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	if cert == nil {
		return &errs.Message{Msg: "certificate is nil"}
	}

	key, err := certStorageKey(attrs)
	if err != nil {
		return err
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := f.storage.Put(context.Background(), key, pemData); err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to write certificate %s", key), Err: err}
	}

	if f.logger != nil {
		f.logger.Debug("certificate saved to file store",
			slog.String("key", key),
			slog.String("subject", cert.Subject.CommonName))
	}

	return nil
}

// Delete removes a certificate from storage.
func (f *FileCertStore) Delete(attrs *types.KeyAttributes) error {
	key, err := certStorageKey(attrs)
	if err != nil {
		return err
	}

	if err := f.storage.Delete(context.Background(), key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrCertNotFound
		}
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to delete certificate %s", key), Err: err}
	}

	if f.logger != nil {
		f.logger.Debug("certificate deleted from file store", slog.String("key", key))
	}

	return nil
}

// ImportCertificate decodes a PEM-encoded certificate and saves it under
// attrs.
func (f *FileCertStore) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, &errs.Message{Msg: "failed to decode PEM block"}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse certificate", Err: err}
	}

	if err := f.Save(attrs, cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// Verify FileCertStore implements CertificateStorer
var _ CertificateStorer = (*FileCertStore)(nil)
