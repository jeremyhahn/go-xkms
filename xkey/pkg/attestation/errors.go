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

package attestation

import "errors"

var (
	// ErrNilTrustStore indicates the trust store provided to the verifier is nil.
	ErrNilTrustStore = errors.New("attestation: nil trust store")

	// ErrNilCertificate indicates a nil certificate was provided for verification.
	ErrNilCertificate = errors.New("attestation: nil certificate")

	// ErrEmptyCertChain indicates an empty certificate chain was provided.
	ErrEmptyCertChain = errors.New("attestation: empty certificate chain")

	// ErrNoTrustAnchors indicates no trust anchors were found for the requested purpose.
	ErrNoTrustAnchors = errors.New("attestation: no trust anchors found for purpose")

	// ErrChainVerification indicates the X.509 chain verification failed.
	ErrChainVerification = errors.New("attestation: chain verification failed")

	// ErrUnsupportedPurpose indicates the certificate purpose is not recognized.
	ErrUnsupportedPurpose = errors.New("attestation: unsupported certificate purpose")

	// ErrTrustStoreQuery indicates a failure querying the trust store.
	ErrTrustStoreQuery = errors.New("attestation: trust store query failed")
)
