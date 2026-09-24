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

// Package ca provides CRL import operations that complement the native
// GenerateCRL / IsRevoked / Revoke flow. Where those operate on the CA's
// own revocation set, ImportDistributionCRLs ingests CRLs published by
// other issuers via their CRLDistributionPoints extension.
package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// ImportDistributionCRLs downloads and stores every CRL listed in the given
// certificate's CRLDistributionPoints extension. CRLs are persisted in the
// object store under "crls/distribution/<sha256(url)>.crl". An absent CRL
// Distribution Points extension is not an error — the method simply returns
// nil so callers can wire it into a generic import pipeline.
//
// Requires the object store to be configured.
//
// Thread-safe: Yes
func (ca *CA) ImportDistributionCRLs(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if len(cert.CRLDistributionPoints) == 0 {
		return nil
	}
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}

	// closeErrs collects reader/response-body Close failures. None of them
	// aborts the import — the CRL itself was already read or was never
	// needed — but a Close failure on a store handle can mean a leaked
	// descriptor, so it is joined into the return rather than dropped.
	var closeErrs []error

	for _, url := range cert.CRLDistributionPoints {
		key := fmt.Sprintf("crls/distribution/%s.crl", hashCRLURL(url))

		// Skip if already imported.
		if reader, err := ca.objectStore.Get(key); err == nil {
			if cerr := reader.Close(); cerr != nil {
				closeErrs = append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to close CRL reader for %s: %v", url, cerr)})
			}
			continue
		}

		// #nosec G107 - URL is from X.509 certificate CRLDP extension (issuer-controlled)
		resp, err := http.Get(url)
		if err != nil {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to download CRL from %s: %v", url, err)})...)
		}
		body, readErr := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			closeErrs = append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to close CRL response body for %s: %v", url, cerr)})
		}
		if readErr != nil {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to read CRL from %s: %v", url, readErr)})...)
		}
		if resp.StatusCode != http.StatusOK {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("CRL download %s returned status %d", url, resp.StatusCode)})...)
		}

		// Validate the CRL parses and has an issuer.
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrCRLGenerationFailed, Detail: fmt.Sprintf("invalid CRL from %s: %v", url, err)})...)
		}
		if crl.Issuer.String() == "" {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrCRLGenerationFailed, Detail: fmt.Sprintf("CRL from %s has empty issuer", url)})...)
		}

		if err := ca.objectStore.Put(key, bytes.NewReader(body)); err != nil {
			return errors.Join(append(closeErrs, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store CRL: %v", err)})...)
		}
	}
	return errors.Join(closeErrs...)
}

// hashCRLURL returns the SHA-256 hex digest of url, used to build stable
// object-store keys for downloaded CRLs.
func hashCRLURL(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
}
