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

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	pairing "github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// enrollmentFamily exercises device enrollment against the live app: the phone
// as an enrollee of an external CA, and its refusal of the TPM-only methods.
//
// Run against an emulator these are informational rather than required. An
// emulator has no TEE keymaster, so the evidence it produces is software-backed
// with an unlocked bootloader -- which a real policy refuses, and should.
// What is checked here is that the exchange works: the phone produces a CSR
// bound to an attestation carrying our challenge, and adopts the credential
// issued for it.
func enrollmentFamily(p *prober) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		p.record("enrollment nonce", false, err, "")
		return
	}
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)

	out, err := p.call(pairing.MethodLocalGetDeviceEnrollmentRequest, map[string]interface{}{
		"nonce":   encodedNonce,
		"subject": "CN=e2eprobe device, O=xKey",
	})
	p.record("local.getDeviceEnrollmentRequest", false, err, "")
	if err != nil {
		return
	}

	var result pairing.LocalGetDeviceEnrollmentRequestResult
	if decodeErr := decodeInto(out, &result); decodeErr != nil {
		p.record("enrollment package decodes", false, decodeErr, "")
		return
	}

	// The format tag exists so a verifier rejects what it cannot read rather
	// than guessing at the bytes.
	if result.Format != pairing.AttestationFormatAndroidKey {
		p.record("enrollment format tag", false,
			&MessageError{Msg: "unexpected format " + result.Format}, "")
	} else {
		p.record("enrollment format tag", false, nil, result.Format)
	}

	// A lone certificate is self-signed and attests nothing.
	if len(result.AttestationChain) < 2 {
		p.record("attestation chain has a path", false,
			&MessageError{Msg: "chain too short to prove anything"}, "")
		return
	}
	p.record("attestation chain has a path", false, nil,
		"certs="+itoa(len(result.AttestationChain))+" level="+result.SecurityLevel)

	chain, chainErr := decodeChain(result.AttestationChain)
	if chainErr != nil {
		p.record("attestation chain parses", false, chainErr, "")
		return
	}
	p.record("attestation chain parses", false, nil, "")

	// The challenge we sent must be inside the extension the TEE wrote. This
	// is what makes the evidence belong to this exchange rather than being a
	// recording of an earlier one.
	desc, descErr := parseChallenge(chain[0])
	switch {
	case descErr != nil:
		p.record("attestation carries our challenge", false, descErr, "")
	case !bytesEqual(desc, nonce):
		p.record("attestation carries our challenge", false,
			&MessageError{Msg: "the attested challenge is not the one we sent"}, "")
	default:
		p.record("attestation carries our challenge", false, nil, "")
	}

	// The CSR must ask for the key the attestation covers. Omitting this check
	// is how a CA ends up certifying a key nobody attested.
	if bindErr := csrBindsToLeaf(result.CSR, chain[0]); bindErr != nil {
		p.record("CSR is bound to the attested key", false, bindErr, "")
	} else {
		p.record("CSR is bound to the attested key", false, nil, "")
	}

	// Issue a credential for that CSR and hand it back, closing the loop.
	certDER, issueErr := issueProbeCredential(result.CSR)
	if issueErr != nil {
		p.record("probe CA issues a credential", false, issueErr, "")
		return
	}
	p.record("probe CA issues a credential", false, nil, "")

	storeOut, storeErr := p.call(pairing.MethodLocalStoreDeviceCredential, map[string]interface{}{
		"certificate": base64.StdEncoding.EncodeToString(certDER),
	})
	p.record("local.storeDeviceCredential", false, storeErr, "")
	if storeErr != nil {
		return
	}

	var stored pairing.LocalStoreDeviceCredentialResult
	if decodeErr := decodeInto(storeOut, &stored); decodeErr != nil {
		p.record("store response decodes", false, decodeErr, "")
		return
	}
	if !stored.Stored || stored.NotAfter == 0 {
		p.record("credential was adopted", false,
			&MessageError{Msg: "the phone did not adopt the credential"}, "")
		return
	}
	p.record("credential was adopted", false, nil, "notAfter="+itoa64(stored.NotAfter))
}

// tpmRefusalFamily proves the phone refuses the TPM2-only enrollment methods
// plainly instead of failing in a way that reads as retryable.
//
// Answering these with a *success* would be the dangerous outcome: credential
// activation is the step that proves the requester holds the hardware it
// claims, so a fake success issues certificates on no evidence.
func tpmRefusalFamily(p *prober) {
	for _, method := range []string{
		pairing.MethodLocalGetTCGCSRIDevID,
		pairing.MethodLocalActivateCredential,
		pairing.MethodLocalGetAttestationQuote,
		pairing.MethodLocalGetIAKPublicKey,
	} {
		_, err := p.call(method, map[string]interface{}{})
		name := method + " is refused as not applicable"

		if err == nil {
			p.record(name, true, &MessageError{
				Msg: "the phone answered a TPM2 method it cannot implement",
			}, "")
			continue
		}

		// The refusal must be specific. METHOD_NOT_FOUND would read as a
		// version mismatch worth retrying past; -32036 says this platform can
		// never serve it and the caller must switch mechanism.
		text := err.Error()
		if !strings.Contains(text, "-32036") {
			p.record(name, true, &MessageError{
				Msg: "expected NOT_APPLICABLE (-32036), got: " + text,
			}, "")
			continue
		}
		p.record(name, true, nil, "NOT_APPLICABLE")
	}
}

// decodeInto re-marshals a raw result map into a typed struct.
func decodeInto(out map[string]json.RawMessage, target interface{}) error {
	encoded, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

// decodeChain turns the wire chain into certificates, leaf first.
func decodeChain(encoded []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(encoded))
	for _, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
