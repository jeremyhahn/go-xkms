package xkms

import (
	"testing"

	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

func TestCARevocationReasonsMatchPkgCA(t *testing.T) {
	cases := map[string][2]int{
		"Unspecified":          {CARevocationReasonUnspecified, pkgca.ReasonUnspecified},
		"KeyCompromise":        {CARevocationReasonKeyCompromise, pkgca.ReasonKeyCompromise},
		"CACompromise":         {CARevocationReasonCACompromise, pkgca.ReasonCACompromise},
		"AffiliationChanged":   {CARevocationReasonAffiliationChanged, pkgca.ReasonAffiliationChanged},
		"Superseded":           {CARevocationReasonSuperseded, pkgca.ReasonSuperseded},
		"CessationOfOperation": {CARevocationReasonCessationOfOperation, pkgca.ReasonCessationOfOperation},
		"CertificateHold":      {CARevocationReasonCertificateHold, pkgca.ReasonCertificateHold},
		"RemoveFromCRL":        {CARevocationReasonRemoveFromCRL, pkgca.ReasonRemoveFromCRL},
		"PrivilegeWithdrawn":   {CARevocationReasonPrivilegeWithdrawn, pkgca.ReasonPrivilegeWithdrawn},
		"AACompromise":         {CARevocationReasonAACompromise, pkgca.ReasonAACompromise},
	}
	for name, v := range cases {
		if v[0] != v[1] {
			t.Errorf("%s: sdk %d != pkg/ca %d", name, v[0], v[1])
		}
		if !pkgca.IsValidRevocationReason(v[0]) {
			t.Errorf("%s: %d is not a valid reason", name, v[0])
		}
	}
}

func TestCARevocationReasonSupersededIsFour(t *testing.T) {
	if CARevocationReasonSuperseded != 4 {
		t.Fatalf("CARevocationReasonSuperseded = %d, want 4", CARevocationReasonSuperseded)
	}
}
