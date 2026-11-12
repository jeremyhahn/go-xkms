package continuous

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// world is a real Appraiser endorsed for one tenant with appraisaltest
// fixtures, and a fixture evidence source that quotes with its AK.
type world struct {
	tenant string
	app    *appraisal.Appraiser
	source *fixtureSource
}

func newWorld(t testing.TB) *world {
	t.Helper()
	ctx := context.Background()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	if err != nil {
		t.Fatal(err)
	}
	app, err := appraisal.NewAppraiser(store)
	if err != nil {
		t.Fatal(err)
	}
	akCA, err := appraisaltest.NewAuthority("AK CA")
	if err != nil {
		t.Fatal(err)
	}
	rvCA, err := appraisaltest.NewAuthority("Reference Value CA")
	if err != nil {
		t.Fatal(err)
	}
	signerCert, signerKey, err := appraisaltest.SignerUnder(rvCA)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := appraisaltest.IssueAttestationKey(akCA, true)
	if err != nil {
		t.Fatal(err)
	}
	pcrs := appraisaltest.PCRValues(0, 4, 7)
	corim, err := appraisaltest.SignCoRIM(pcrs, signerKey, []*x509.Certificate{signerCert})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{tenant: "acme", app: app}
	for _, tenant := range []string{"acme", "globex"} {
		if _, err := app.PutEndorsement(ctx, tenant, &appraisal.PutEndorsementRequest{Name: "ak-ca", Kind: appraisal.EndorsementAKRoot, CertificatePEM: akCA.CertificatePEM()}); err != nil {
			t.Fatal(err)
		}
		if _, err := app.PutEndorsement(ctx, tenant, &appraisal.PutEndorsementRequest{Name: "rv-ca", Kind: appraisal.EndorsementReferenceSigner, CertificatePEM: rvCA.CertificatePEM()}); err != nil {
			t.Fatal(err)
		}
		if _, err := app.PutReferenceValues(ctx, tenant, &appraisal.PutReferenceValuesRequest{Name: "golden", SignedCoRIM: corim}); err != nil {
			t.Fatal(err)
		}
	}
	w.source = &fixtureSource{ak: ak, pcrs: pcrs, tampered: map[string]bool{}, nonces: map[string][][]byte{}}
	return w
}

// fixtureSource quotes the golden PCRs with the fixture AK, or divergent
// PCRs for a tampered device, and records every nonce it was given.
type fixtureSource struct {
	ak       *appraisaltest.AttestationKey
	pcrs     map[uint32][]byte
	mu       sync.Mutex
	tampered map[string]bool
	nonces   map[string][][]byte
}

func (s *fixtureSource) tamper(deviceID string) {
	s.mu.Lock()
	s.tampered[deviceID] = true
	s.mu.Unlock()
}

func (s *fixtureSource) noncesFor(deviceID string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nonces[deviceID]
}

func (s *fixtureSource) Collect(_ context.Context, _, deviceID string, nonce []byte) (*appraisal.AppraiseQuoteRequest, error) {
	s.mu.Lock()
	s.nonces[deviceID] = append(s.nonces[deviceID], append([]byte(nil), nonce...))
	pcrs := s.pcrs
	if s.tampered[deviceID] {
		pcrs = make(map[uint32][]byte, len(s.pcrs))
		for index, value := range s.pcrs {
			pcrs[index] = append([]byte(nil), value...)
		}
		pcrs[7][0] ^= 0xff
	}
	s.mu.Unlock()
	quote, err := appraisaltest.SignQuote(s.ak, pcrs, nonce)
	if err != nil {
		return nil, err
	}
	return &appraisal.AppraiseQuoteRequest{
		AKCertificatePEM: s.ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            nonce,
		PCRs:             pcrs,
		ReferenceValues:  "golden",
	}, nil
}
