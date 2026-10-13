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

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	pairing "github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Every enrollment step is informational: an emulator cannot produce evidence
// a real policy accepts, so a deviation is recorded without failing the run.
func requireAllOptional(t *testing.T, p *prober) {
	t.Helper()
	for _, s := range p.steps {
		if s.required {
			t.Fatalf("enrollment step %q is required; every enrollment step is informational", s.name)
		}
	}
}

func TestEnrollmentFamily_RecordsEachDeviationInTheEvidence(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(t *testing.T, ph *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult)
		step       string
		wantDetail string
		wantStore  bool
	}{
		{
			name: "unknown format tag",
			mutate: func(_ *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				res.Format = "tpm2-quote"
			},
			step: "enrollment format tag", wantDetail: "unexpected format tpm2-quote", wantStore: true,
		},
		{
			name: "lone self-signed certificate",
			mutate: func(_ *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				res.AttestationChain = res.AttestationChain[:1]
			},
			step: "attestation chain has a path", wantDetail: "chain too short",
		},
		{
			name: "chain entry is not base64",
			mutate: func(_ *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				res.AttestationChain[1] = "!!"
			},
			step: "attestation chain parses", wantDetail: "illegal base64",
		},
		{
			name: "attestation over an earlier exchange's challenge",
			mutate: func(t *testing.T, ph *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				replayed := attesttest.AttestedLeafDER(t, ph.attestCA, ph.deviceKey, []byte("an earlier nonce"),
					xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
				res.AttestationChain[0] = b64(replayed)
			},
			step: "attestation carries our challenge", wantDetail: "not the one we sent", wantStore: true,
		},
		{
			name: "leaf carries no attestation extension",
			mutate: func(t *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				plain, err := selfSignedCert("no attestation")
				if err != nil {
					t.Fatalf("selfSignedCert: %v", err)
				}
				res.AttestationChain[0] = b64(plain)
			},
			step: "attestation carries our challenge", wantDetail: " -> ", wantStore: true,
		},
		{
			name: "CSR asks for a key nobody attested",
			mutate: func(t *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				res.CSR = csrFor(t, newKey(t))
			},
			step: "CSR is bound to the attested key", wantDetail: "the CSR key is not the attested key",
			wantStore: true,
		},
		{
			name: "CSR does not parse",
			mutate: func(_ *testing.T, _ *phone, res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				res.CSR = []byte("not a CSR")
			},
			step: "probe CA issues a credential", wantDetail: " -> ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			ph.mutateEnrollment = func(res *pairing.LocalGetDeviceEnrollmentRequestResult) {
				tt.mutate(t, ph, res)
			}
			p := ph.prober()

			enrollmentFamily(p)

			requireFailedStep(t, p, tt.step, tt.wantDetail)
			requireAllOptional(t, p)
			if got := ph.called(pairing.MethodLocalStoreDeviceCredential); got != tt.wantStore {
				t.Fatalf("storeDeviceCredential called = %v, want %v", got, tt.wantStore)
			}
		})
	}
}

func TestEnrollmentFamily_RecordsACredentialThePhoneDidNotAdopt(t *testing.T) {
	ph := newPhone(t)
	ph.handlers[pairing.MethodLocalStoreDeviceCredential] = func(map[string]interface{}) (interface{}, error) {
		return &pairing.LocalStoreDeviceCredentialResult{Stored: false}, nil
	}
	p := ph.prober()

	enrollmentFamily(p)

	requireFailedStep(t, p, "credential was adopted", "did not adopt")
	requireAllOptional(t, p)
}

func TestEnrollmentFamily_StopsWhenThePhoneRefuses(t *testing.T) {
	tests := []struct {
		name   string
		method string
		answer phoneHandler
		step   string
	}{
		{"request refused", pairing.MethodLocalGetDeviceEnrollmentRequest, notApplicable,
			"local.getDeviceEnrollmentRequest"},
		{"package undecodable", pairing.MethodLocalGetDeviceEnrollmentRequest,
			func(map[string]interface{}) (interface{}, error) {
				return map[string]interface{}{"attestationChain": "not an array"}, nil
			}, "enrollment package decodes"},
		{"store refused", pairing.MethodLocalStoreDeviceCredential, notApplicable,
			"local.storeDeviceCredential"},
		{"store answer undecodable", pairing.MethodLocalStoreDeviceCredential,
			func(map[string]interface{}) (interface{}, error) {
				return map[string]interface{}{"stored": "yes"}, nil
			}, "store response decodes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			ph.handlers[tt.method] = tt.answer
			p := ph.prober()

			enrollmentFamily(p)

			requireFailedStep(t, p, tt.step, " -> ")
			requireAllOptional(t, p)
			if last := p.steps[len(p.steps)-1]; last.name != tt.step {
				t.Fatalf("the family continued past %q to %q", tt.step, last.name)
			}
		})
	}
}

func TestDecodeInto(t *testing.T) {
	var stored pairing.LocalStoreDeviceCredentialResult
	ok := map[string]json.RawMessage{"stored": json.RawMessage(`true`), "notAfter": json.RawMessage(`99`)}
	if err := decodeInto(ok, &stored); err != nil {
		t.Fatalf("decodeInto: %v", err)
	}
	if !stored.Stored || stored.NotAfter != 99 {
		t.Fatalf("decoded %+v", stored)
	}

	wrongType := map[string]json.RawMessage{"stored": json.RawMessage(`"yes"`)}
	if err := decodeInto(wrongType, &stored); err == nil {
		t.Fatal("decodeInto accepted a string for a bool field")
	}
}

func TestDecodeChain(t *testing.T) {
	ca := attesttest.NewCA(t, "chain root")
	leafDER := attesttest.AttestedLeafDER(t, ca, newKey(t), []byte("nonce"),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	chain, err := decodeChain([]string{b64(leafDER), b64(ca.Cert.Raw)})
	if err != nil {
		t.Fatalf("decodeChain: %v", err)
	}
	if len(chain) != 2 || !bytes.Equal(chain[0].Raw, leafDER) || !bytes.Equal(chain[1].Raw, ca.Cert.Raw) {
		t.Fatal("decodeChain did not keep the leaf-first order")
	}

	for name, entry := range map[string]string{
		"not base64":     "!!",
		"not a DER cert": b64([]byte("not a certificate")),
	} {
		if _, err := decodeChain([]string{entry}); err == nil {
			t.Fatalf("decodeChain accepted an entry that is %s", name)
		}
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "probe subject"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}
