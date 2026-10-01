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

package evidence_test

import (
	"errors"
	"testing"

	pkgevidence "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/sdk/go/evidence"
)

// The aliases are the implementation's own types, so values cross the SDK
// boundary without conversion. These assignments fail to compile otherwise.
var (
	_ *pkgevidence.Quote               = (*evidence.Quote)(nil)
	_ *pkgevidence.EventLog            = (*evidence.EventLog)(nil)
	_ *pkgevidence.Error               = (*evidence.Error)(nil)
	_ pkgevidence.QuoteInput           = evidence.QuoteInput{}
	_ *tpm2.CertifyVerification        = (*evidence.CertifyVerification)(nil)
	_ peer.DevIDPolicy                 = evidence.DevIDPolicy{}
	_ pkgevidence.EKCertificateOptions = evidence.EKCertificateOptions{}
)

func TestAliasesBehaveAsTheImplementation(t *testing.T) {
	_, err := evidence.ParseQuote(nil)
	var e *pkgevidence.Error
	if !errors.As(err, &e) || e.Class != evidence.ClassAbsent || !errors.Is(err, evidence.ErrAbsent) {
		t.Fatalf("ParseQuote(nil) = %v, want an absent *Error", err)
	}
	if _, err := evidence.ParseEventLog([]byte{1}); !errors.Is(err, evidence.ErrEventLogMalformed) {
		t.Fatalf("ParseEventLog = %v, want ErrEventLogMalformed", err)
	}
	if !evidence.OIDTCGKpEKCertificate.Equal(pkgevidence.OIDTCGKpEKCertificate) {
		t.Fatal("OID alias differs")
	}
	if _, err := evidence.VerifyCertifyRaw(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("VerifyCertifyRaw accepted empty input")
	}
}
