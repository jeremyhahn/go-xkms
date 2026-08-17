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

//go:build ble

package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// CA source names for --ca.
const (
	caSourceLocal = "local"
	caSourceXKMS  = "xkms"
)

// enrollmentCertProfile is the certificate profile requested for a device
// credential. It is an LDevID in the IEEE 802.1AR sense -- a locally
// significant, re-issuable device identity -- which is what the idevid profile
// models here.
const enrollmentCertProfile = "idevid"

// androidAttestationRoots builds the pool the phone's chain must reach.
//
// These are the Google hardware attestation roots. They are what turns the
// chain from "certificates the phone sent" into evidence: without an anchor a
// device can mint its own chain and attest whatever it likes.
func androidAttestationRoots() (*x509.CertPool, error) {
	store, err := openTrustStore()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open trust store", Err: err}
	}
	defer func() { _ = store.Close() }()

	verifier, err := attestation.NewVerifier(store, truststore.LoadEmbeddedRoots)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create attestation verifier", Err: err}
	}

	pool, err := verifier.BuildTrustPool(truststore.PurposeAndroidHardware)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to build the attestation trust pool", Err: err}
	}
	return pool, nil
}

// signEnrollmentCSR gets the phone's CSR signed and returns the certificate and
// its issuer chain, both DER.
//
// The two CA sources differ in who is authoritative, not merely in who holds
// the key:
//
//   - local: this host already applied EnrollmentPolicy and decided. The CSR is
//     sent without evidence, because the decision has been made here.
//   - xkms: the server is the enterprise CA and applies its own policy, so the
//     evidence travels with the request and the server re-verifies it. The
//     local check still runs first, so a device that this host would refuse is
//     never put to the server.
func signEnrollmentCSR(
	ctx context.Context,
	opts *enrollPhoneOptions,
	result *phone.LocalGetDeviceEnrollmentRequestResult,
	nonce []byte,
	decision *phone.EnrollmentDecision,
) ([]byte, [][]byte, error) {
	source := strings.ToLower(strings.TrimSpace(opts.CASource))
	if source == "" {
		source = caSourceLocal
	}
	if source != caSourceLocal && source != caSourceXKMS {
		return nil, nil, fmt.Errorf("%w: unknown --ca %q, expected local or xkms",
			ErrEnrollPhoneNoCA, opts.CASource)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: result.CSR,
	})
	if csrPEM == nil {
		return nil, nil, fmt.Errorf("%w: the phone's CSR could not be encoded",
			ErrEnrollPhoneRefused)
	}

	req := &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      enrollmentCertProfile,
		ValidityDays: validityDaysUntil(decision.NotAfter),
	}

	if source == caSourceXKMS {
		chain, err := decodeChainDER(result.AttestationChain)
		if err != nil {
			return nil, nil, err
		}
		req.AttestationFormat = phone.AttestationFormatAndroidKey
		req.AttestationChain = chain
		req.AttestationNonce = nonce
		fmt.Println("Submitting to the xkms enterprise CA with attestation evidence...")
	} else {
		fmt.Println("Signing with this host's CA...")
	}

	client, err := getSDKClient(nil)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrEnrollPhoneNoCA, Cause: err}
	}
	defer func() { _ = client.Close() }()

	resp, err := client.SignCSR(ctx, req)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrEnrollPhoneRefused, Cause: err}
	}

	certDER, err := firstPEMBlock(resp.CertificatePEM, "CERTIFICATE")
	if err != nil {
		return nil, nil, err
	}

	chainDER, err := allPEMBlocks(resp.ChainPEM, "CERTIFICATE")
	if err != nil {
		return nil, nil, err
	}

	return certDER, chainDER, nil
}

// validityDaysUntil converts a deadline into whole days, rounding up so a
// credential is never issued shorter than policy asked for.
//
// A deadline already in the past would round to zero or negative, which some
// CAs read as "use the default" -- a longer credential than intended. One day
// is the floor instead, so a misconfiguration expires quickly rather than
// silently lasting longer.
func validityDaysUntil(notAfter time.Time) int {
	remaining := time.Until(notAfter)
	if remaining <= 0 {
		return 1
	}
	days := int(math.Ceil(remaining.Hours() / 24))
	if days < 1 {
		return 1
	}
	return days
}

// decodeChainDER converts the wire chain into DER for the transport request.
func decodeChainDER(encoded []string) ([][]byte, error) {
	out := make([][]byte, 0, len(encoded))
	for i, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("%w: attestation certificate %d is not valid base64: %v",
				ErrEnrollPhoneRefused, i, err)
		}
		out = append(out, der)
	}
	return out, nil
}

// firstPEMBlock extracts the first block of the wanted type.
func firstPEMBlock(data []byte, want string) ([]byte, error) {
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == want {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("%w: the CA returned no %s", ErrEnrollPhoneRefused, want)
}

// allPEMBlocks extracts every block of the wanted type, in order.
func allPEMBlocks(data []byte, want string) ([][]byte, error) {
	var out [][]byte
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == want {
			out = append(out, block.Bytes)
		}
	}
	return out, nil
}
