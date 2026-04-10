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

package tpm2

import (
	"crypto/x509"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

var (
	ErrIDevIDCertNotFound     = errors.New("tpm: IDevID certificate not found")
	ErrIAKCertNotFound        = errors.New("tpm: IAK certificate not found")
	ErrCertPublicKeyMismatch  = errors.New("tpm: certificate public key does not match TPM key")
	ErrCertStoreNotConfigured = errors.New("tpm: certificate store not configured")
)

// ProvisionIDevIDCert stores the IDevID certificate.
// If CertHandle is 0, the certificate is stored in the certificate store.
// If CertHandle is set, the certificate is stored in TPM NVRAM.
func (tpm *TPM2) ProvisionIDevIDCert(cert *x509.Certificate) error {
	if tpm.config.IDevID == nil {
		return ErrNotConfigured
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return err
	}

	// Validate public key matches
	if err := validateCertPublicKey(cert, idevidAttrs); err != nil {
		return err
	}

	if tpm.config.IDevID.CertHandle == 0 {
		return tpm.writeCertToStore(idevidAttrs, cert)
	}

	return tpm.writeCertToNVRAM(tpm2.TPMHandle(tpm.config.IDevID.CertHandle), cert.Raw)
}

// IDevIDCertificate retrieves the IDevID certificate.
// If CertHandle is 0, the certificate is read from the certificate store.
// If CertHandle is set, the certificate is read from TPM NVRAM.
func (tpm *TPM2) IDevIDCertificate() (*x509.Certificate, error) {
	if tpm.config.IDevID == nil {
		return nil, ErrNotConfigured
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return nil, err
	}

	if tpm.config.IDevID.CertHandle == 0 {
		if tpm.certStore == nil {
			return nil, ErrCertStoreNotConfigured
		}
		cert, err := tpm.certStore.Get(idevidAttrs)
		if err != nil {
			if err == store.ErrCertNotFound {
				return nil, ErrIDevIDCertNotFound
			}
			return nil, err
		}
		return cert, nil
	}

	certDER, err := tpm.readCertFromNVRAM(tpm2.TPMHandle(tpm.config.IDevID.CertHandle))
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// DeleteIDevIDCertificate removes the IDevID certificate.
// If CertHandle is 0, the certificate is deleted from the certificate store.
// If CertHandle is set, the NV index is undefined from TPM NVRAM.
func (tpm *TPM2) DeleteIDevIDCertificate() error {
	if tpm.config.IDevID == nil {
		return ErrNotConfigured
	}

	if tpm.config.IDevID.CertHandle == 0 {
		if tpm.certStore == nil {
			return ErrCertStoreNotConfigured
		}
		idevidAttrs, err := tpm.IDevIDAttributes()
		if err != nil {
			return err
		}
		return tpm.certStore.Delete(idevidAttrs)
	}

	return tpm.deleteCertFromNVRAM(tpm2.TPMHandle(tpm.config.IDevID.CertHandle))
}

// ProvisionIAKCert stores the IAK certificate.
// If CertHandle is 0, the certificate is stored in the certificate store.
// If CertHandle is set, the certificate is stored in TPM NVRAM.
func (tpm *TPM2) ProvisionIAKCert(cert *x509.Certificate) error {
	if tpm.config.IAK == nil {
		return ErrNotConfigured
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return err
	}

	// Validate public key matches
	if err := validateCertPublicKey(cert, iakAttrs); err != nil {
		return err
	}

	if tpm.config.IAK.CertHandle == 0 {
		return tpm.writeCertToStore(iakAttrs, cert)
	}

	return tpm.writeCertToNVRAM(tpm2.TPMHandle(tpm.config.IAK.CertHandle), cert.Raw)
}

// IAKCertificate retrieves the IAK certificate.
// If CertHandle is 0, the certificate is read from the certificate store.
// If CertHandle is set, the certificate is read from TPM NVRAM.
func (tpm *TPM2) IAKCertificate() (*x509.Certificate, error) {
	if tpm.config.IAK == nil {
		return nil, ErrNotConfigured
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, err
	}

	if tpm.config.IAK.CertHandle == 0 {
		if tpm.certStore == nil {
			return nil, ErrCertStoreNotConfigured
		}
		cert, err := tpm.certStore.Get(iakAttrs)
		if err != nil {
			if err == store.ErrCertNotFound {
				return nil, ErrIAKCertNotFound
			}
			return nil, err
		}
		return cert, nil
	}

	certDER, err := tpm.readCertFromNVRAM(tpm2.TPMHandle(tpm.config.IAK.CertHandle))
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// DeleteIAKCertificate removes the IAK certificate.
// If CertHandle is 0, the certificate is deleted from the certificate store.
// If CertHandle is set, the NV index is undefined from TPM NVRAM.
func (tpm *TPM2) DeleteIAKCertificate() error {
	if tpm.config.IAK == nil {
		return ErrNotConfigured
	}

	if tpm.config.IAK.CertHandle == 0 {
		if tpm.certStore == nil {
			return ErrCertStoreNotConfigured
		}
		iakAttrs, err := tpm.IAKAttributes()
		if err != nil {
			return err
		}
		return tpm.certStore.Delete(iakAttrs)
	}

	return tpm.deleteCertFromNVRAM(tpm2.TPMHandle(tpm.config.IAK.CertHandle))
}
