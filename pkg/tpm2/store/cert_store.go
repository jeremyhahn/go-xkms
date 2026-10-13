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
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// BlobCertStore implements CertificateStorer over a BlobStore: a certificate
// is the FSEXT_CERTIFICATE blob of its object, stored beside the object's key
// material rather than in a separate cert-only store, so there is exactly one
// place a device's TPM state lives.
//
// This is what gives a hardware device the persistent certificate store the
// in-process TPM simulator's development-only MemoryCertStore does not need
// (a fresh throwaway IAK certificate is re-minted every time the simulator
// opens): a hardware TPM's IAK certificate is issued once, by enroll-01, and
// must still be there when a later, separate process runs device-attest-01
// (go-xkms#1100).
type BlobCertStore struct {
	logger *slog.Logger
	blobs  *BlobStore
}

// NewBlobCertStore returns a certificate store that keeps certificates in
// blobs.
func NewBlobCertStore(logger *slog.Logger, blobs *BlobStore) CertificateStorer {
	return &BlobCertStore{logger: logger, blobs: blobs}
}

// certName returns the blob name of the certificate of attrs: the Common
// Name, parent-prefixed when attrs has a parent, mirroring MemoryCertStore's
// addressing so the two stores name the same certificate identically.
func certName(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil || attrs.CN == "" {
		return "", ErrEmptyKeyCN
	}
	if attrs.Parent != nil && attrs.Parent.CN != "" {
		return attrs.Parent.CN + "/" + attrs.CN, nil
	}
	return attrs.CN, nil
}

// Get returns the certificate of attrs, or ErrCertNotFound.
func (c *BlobCertStore) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	name, err := certName(attrs)
	if err != nil {
		return nil, err
	}
	der, err := c.blobs.read(context.Background(), name, FSEXT_CERTIFICATE)
	if errors.Is(err, ErrBlobNotFound) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse certificate " + name, Err: err}
	}
	return cert, nil
}

// Save stores cert under attrs, replacing any certificate already stored
// there -- a device re-enrolling replaces its previous certificate, it does
// not accumulate one per enrollment.
func (c *BlobCertStore) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	if cert == nil {
		return &errs.Message{Msg: "certificate is nil"}
	}
	name, err := certName(attrs)
	if err != nil {
		return err
	}
	if err := c.blobs.write(context.Background(), name, FSEXT_CERTIFICATE, cert.Raw, true); err != nil {
		return err
	}
	if c.logger != nil {
		c.logger.Debug("certificate saved to blob store",
			slog.String("name", name),
			slog.String("subject", cert.Subject.CommonName))
	}
	return nil
}

// Delete removes the certificate of attrs, or reports ErrCertNotFound.
func (c *BlobCertStore) Delete(attrs *types.KeyAttributes) error {
	name, err := certName(attrs)
	if err != nil {
		return err
	}
	removed, err := c.blobs.remove(context.Background(), name, FSEXT_CERTIFICATE)
	if err != nil {
		return err
	}
	if !removed {
		return ErrCertNotFound
	}
	return nil
}

// ImportCertificate decodes a PEM-encoded certificate and saves it under
// attrs.
func (c *BlobCertStore) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, &errs.Message{Msg: "failed to decode PEM block"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse certificate", Err: err}
	}
	if err := c.Save(attrs, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// Verify BlobCertStore implements CertificateStorer
var _ CertificateStorer = (*BlobCertStore)(nil)
