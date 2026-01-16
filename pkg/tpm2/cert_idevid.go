// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

var (
	ErrIDevIDCertNotFound     = errors.New("tpm: IDevID certificate not found")
	ErrIAKCertNotFound        = errors.New("tpm: IAK certificate not found")
	ErrCertPublicKeyMismatch  = errors.New("tpm: certificate public key does not match TPM key")
	ErrCertStoreNotConfigured = errors.New("tpm: certificate store not configured")
)

// WriteIDevIDCertificate stores the IDevID certificate.
// If CertHandle is 0, the certificate is stored in the certificate store.
// If CertHandle is set, the certificate is stored in TPM NVRAM.
func (tpm *TPM2) WriteIDevIDCertificate(cert *x509.Certificate) error {
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

// ReadIDevIDCertificate retrieves the IDevID certificate.
// If CertHandle is 0, the certificate is read from the certificate store.
// If CertHandle is set, the certificate is read from TPM NVRAM.
func (tpm *TPM2) ReadIDevIDCertificate() (*x509.Certificate, error) {
	if tpm.config.IDevID == nil {
		return nil, ErrNotConfigured
	}

	idevidAttrs, err := tpm.IDevIDAttributes()
	if err != nil {
		return nil, err
	}

	if tpm.config.IDevID.CertHandle == 0 {
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
		idevidAttrs, err := tpm.IDevIDAttributes()
		if err != nil {
			return err
		}
		return tpm.certStore.Delete(idevidAttrs)
	}

	return tpm.deleteCertFromNVRAM(tpm2.TPMHandle(tpm.config.IDevID.CertHandle))
}

// WriteIAKCertificate stores the IAK certificate.
// If CertHandle is 0, the certificate is stored in the certificate store.
// If CertHandle is set, the certificate is stored in TPM NVRAM.
func (tpm *TPM2) WriteIAKCertificate(cert *x509.Certificate) error {
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

// ReadIAKCertificate retrieves the IAK certificate.
// If CertHandle is 0, the certificate is read from the certificate store.
// If CertHandle is set, the certificate is read from TPM NVRAM.
func (tpm *TPM2) ReadIAKCertificate() (*x509.Certificate, error) {
	if tpm.config.IAK == nil {
		return nil, ErrNotConfigured
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, err
	}

	if tpm.config.IAK.CertHandle == 0 {
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
		iakAttrs, err := tpm.IAKAttributes()
		if err != nil {
			return err
		}
		return tpm.certStore.Delete(iakAttrs)
	}

	return tpm.deleteCertFromNVRAM(tpm2.TPMHandle(tpm.config.IAK.CertHandle))
}

// writeCertToStore writes a certificate to the certificate store.
func (tpm *TPM2) writeCertToStore(keyAttrs *types.KeyAttributes, cert *x509.Certificate) error {
	if tpm.certStore == nil {
		return ErrCertStoreNotConfigured
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	_, err := tpm.certStore.ImportCertificate(keyAttrs, certPEM)
	return err
}

// writeCertToNVRAM writes a DER-encoded certificate to TPM NVRAM.
func (tpm *TPM2) writeCertToNVRAM(nvIndex tpm2.TPMHandle, certDER []byte) error {
	tpm.logger.Debug("writing certificate to NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)),
		slog.Int("size_bytes", len(certDER)))

	// Define NV space
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm.algID,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					AuthWrite:  true,
					OwnerRead:  true,
					AuthRead:   true,
					NoDA:       true,
					NT:         tpm2.TPMNT(0x01),
				},
				DataSize: uint16(len(certDER)),
			}),
	}

	_, err := defs.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to define NV space", slog.String("error", err.Error()))
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get NV public info", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to compute NV name", slog.String("error", err.Error()))
		return err
	}

	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: certDER,
		},
		Offset: 0,
	}

	if _, err := write.Execute(tpm.transport); err != nil {
		tpm.logger.Error("failed to write NV data", slog.String("error", err.Error()))
		return err
	}

	return nil
}

// readCertFromNVRAM reads a DER-encoded certificate from TPM NVRAM.
func (tpm *TPM2) readCertFromNVRAM(nvIndex tpm2.TPMHandle) ([]byte, error) {
	tpm.logger.Debug("reading certificate from NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)))

	// Read NV public to get the Name and DataSize
	nvPub, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}

	pub, err := nvPub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	// Read NV data
	nvRead, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   nvPub.NVName,
		},
		Size:   pub.DataSize,
		Offset: 0,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}

	return nvRead.Data.Buffer, nil
}

// deleteCertFromNVRAM undefines an NV index from TPM NVRAM.
func (tpm *TPM2) deleteCertFromNVRAM(nvIndex tpm2.TPMHandle) error {
	tpm.logger.Debug("deleting certificate from NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)))

	_, err := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: nvIndex,
	}.Execute(tpm.transport)

	return err
}

// validateCertPublicKey validates that the certificate's public key matches the TPM key.
func validateCertPublicKey(cert *x509.Certificate, keyAttrs *types.KeyAttributes) error {
	if keyAttrs == nil || keyAttrs.TPMAttributes == nil {
		return ErrInvalidKeyAttributes
	}

	// Get the public key bytes from the TPM key
	tpmPubBytes := keyAttrs.TPMAttributes.BPublic.Bytes()

	// For now, we verify by comparing the public key from the certificate
	// with the TPM's public area. This is a basic validation.
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	// The TPM public area format is different from PKIX, so we need to
	// reconstruct the public key from the TPM public area and compare.
	pub := keyAttrs.TPMAttributes.Public

	var reconstructedPubDER []byte

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return err
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return err
		}
		reconstructedPubDER, err = x509.MarshalPKIXPublicKey(rsaPub)
		if err != nil {
			return err
		}

	case tpm2.TPMAlgECC:
		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return err
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return err
		}
		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return err
		}
		ecPub := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		reconstructedPubDER, err = x509.MarshalPKIXPublicKey(ecPub)
		if err != nil {
			return err
		}

	default:
		// For unsupported types, just verify that the public bytes are present
		if len(tpmPubBytes) == 0 {
			return ErrInvalidKeyAttributes
		}
		return nil
	}

	if !bytes.Equal(certPubDER, reconstructedPubDER) {
		return ErrCertPublicKeyMismatch
	}

	return nil
}
