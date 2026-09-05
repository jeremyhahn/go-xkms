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

package ca

// The IAK and the IDevID certificate of one TCG-CSR-IDEVID enrollment are
// stored in a certificate store keyed by subject common name. Until #371 both
// were issued under the request subject, so the IDevID record replaced the IAK
// record and the CA could neither list, revoke nor return the IAK it had
// signed. These tests drive the real SignTCGCSRIDevID path with a CSR
// assembled entirely in software -- the IAK certifies the IDevID through a
// TPM2_Certify structure signed by the IAK key, and the IDevID key signs the
// CSR contents -- so the verification the CA performs is the production one.
//
// Mutation record: reverting the IAK subject to request.Subject.ToPkixName()
// in SignTCGCSRIDevID fails TestSignTCGCSRIDevID_IAKRecordSurvivesIDevIDIssuance
// (one record in the store instead of two; IAK lookup returns the IDevID) and
// TestIAKCertificate_ReturnsEnrolledIAK (ErrCertificateNotFound).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	gotpm "github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

const (
	softwareCSRModel  = "SuperMicro X10"
	softwareCSRSerial = "SN-371"
	tcgStructVersion  = uint32(0x00000100)
)

// softwareTCGCSR is a TCG-CSR-IDEVID built without a TPM. Both keys are
// software ECDSA P-256 keys whose public areas carry the object attributes
// the CA requires of a TPM-resident IAK and IDevID.
type softwareTCGCSR struct {
	csr       *tpm2.TCG_CSR_IDEVID
	iakKey    *ecdsa.PrivateKey
	idevidKey *ecdsa.PrivateKey
}

// eccPublicArea encodes an ECDSA P-256 public key as a TPMT_PUBLIC with the
// fixed, TPM-resident, signing attributes; restricted selects the IAK shape.
func eccPublicArea(t *testing.T, pub *ecdsa.PublicKey, restricted bool) []byte {
	t.Helper()
	uncompressed, err := pub.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	coordLen := (len(uncompressed) - 1) / 2
	area := gotpm.TPMTPublic{
		Type:    gotpm.TPMAlgECC,
		NameAlg: gotpm.TPMAlgSHA256,
		ObjectAttributes: gotpm.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
		Parameters: gotpm.NewTPMUPublicParms(gotpm.TPMAlgECC, &gotpm.TPMSECCParms{
			CurveID: gotpm.TPMECCNistP256,
			Scheme: gotpm.TPMTECCScheme{
				Scheme: gotpm.TPMAlgECDSA,
				Details: gotpm.NewTPMUAsymScheme(gotpm.TPMAlgECDSA,
					&gotpm.TPMSSigSchemeECDSA{HashAlg: gotpm.TPMAlgSHA256}),
			},
		}),
		Unique: gotpm.NewTPMUPublicID(gotpm.TPMAlgECC, &gotpm.TPMSECCPoint{
			X: gotpm.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
			Y: gotpm.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
		}),
	}
	return gotpm.Marshal(area)
}

// certifySubjectWithIAK produces the TPM2_Certify attestation of subjectPub
// signed by iakKey, in the raw r||s form the CSR carries.
func certifySubjectWithIAK(t *testing.T, iakKey *ecdsa.PrivateKey, subjectPub []byte) (certifyInfo, signature []byte) {
	t.Helper()
	subject, err := gotpm.Unmarshal[gotpm.TPMTPublic](subjectPub)
	if err != nil {
		t.Fatalf("unmarshal subject public area: %v", err)
	}
	name, err := gotpm.ObjectName(subject)
	if err != nil {
		t.Fatalf("compute subject name: %v", err)
	}
	attest := gotpm.TPMSAttest{
		Magic: gotpm.TPMGeneratedValue,
		Type:  gotpm.TPMSTAttestCertify,
		Attested: gotpm.NewTPMUAttest(gotpm.TPMSTAttestCertify, &gotpm.TPMSCertifyInfo{
			Name:          *name,
			QualifiedName: *name,
		}),
	}
	certifyInfo = gotpm.Marshal(attest)
	digest := sha256.Sum256(certifyInfo)
	r, s, err := ecdsa.Sign(rand.Reader, iakKey, digest[:])
	if err != nil {
		t.Fatalf("sign certify info: %v", err)
	}
	signature = make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return certifyInfo, signature
}

// buildSoftwareTCGCSR assembles a verifiable TCG-CSR-IDEVID for a device with
// the given product model and serial number, using the single-pass strategy
// in which the IDevID key signs the CSR contents.
func buildSoftwareTCGCSR(t *testing.T, model, serial string) *softwareTCGCSR {
	t.Helper()

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	idevidKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate idevid key: %v", err)
	}

	attestPub := eccPublicArea(t, &iakKey.PublicKey, true)
	signingPub := eccPublicArea(t, &idevidKey.PublicKey, false)
	certifyInfo, certifySig := certifySubjectWithIAK(t, iakKey, signingPub)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ek key: %v", err)
	}
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ek-" + serial},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, ekTemplate, ekTemplate, &ekKey.PublicKey, ekKey)
	if err != nil {
		t.Fatalf("create ek certificate: %v", err)
	}

	content := &tpm2.TCG_IDEVID_CONTENT{
		ProdModel:         []byte(model),
		ProdSerial:        []byte(serial),
		EkCert:            ekDER,
		AttestPub:         attestPub,
		SigningPub:        signingPub,
		SgnCertifyInfo:    certifyInfo,
		SgnCertifyInfoSig: certifySig,
	}
	putSize := func(field *[4]byte, n int) {
		binary.BigEndian.PutUint32(field[:], uint32(n)) // #nosec G115 -- test sizes are small
	}
	putSize(&content.StructVer, int(tcgStructVersion))
	putSize(&content.HashAlgoId, int(gotpm.TPMAlgSHA256))
	putSize(&content.HashSz, sha256.Size)
	putSize(&content.ProdModelSz, len(content.ProdModel))
	putSize(&content.ProdSerialSz, len(content.ProdSerial))
	putSize(&content.EkCertSZ, len(content.EkCert))
	putSize(&content.AttestPubSZ, len(content.AttestPub))
	putSize(&content.SigningPubSZ, len(content.SigningPub))
	putSize(&content.SgnCertifyInfoSZ, len(content.SgnCertifyInfo))
	putSize(&content.SgnCertifyInfoSignatureSZ, len(content.SgnCertifyInfoSig))

	packed, err := tpm2.PackIDevIDContent(content)
	if err != nil {
		t.Fatalf("pack csr contents: %v", err)
	}
	digest := sha256.Sum256(packed)
	csrSig, err := ecdsa.SignASN1(rand.Reader, idevidKey, digest[:])
	if err != nil {
		t.Fatalf("sign csr contents: %v", err)
	}

	csr := &tpm2.TCG_CSR_IDEVID{CsrContents: *content, Signature: csrSig}
	putSize(&csr.StructVer, int(tcgStructVersion))
	putSize(&csr.Contents, len(packed))
	putSize(&csr.SigSz, len(csrSig))

	// The builder must produce what the CA will accept; a defect here would
	// otherwise surface as an opaque verification failure in every test.
	if _, _, err := tpm2.VerifyTCG_CSR_IDevID_Stateless(csr, x509.ECDSAWithSHA256); err != nil {
		t.Fatalf("software csr does not verify: %v", err)
	}

	return &softwareTCGCSR{csr: csr, iakKey: iakKey, idevidKey: idevidKey}
}

// enrollSoftwareDevice runs SignTCGCSRIDevID for a software device whose
// IDevID subject mirrors the ACME enroll-01 handler: "<model>-<serial>".
func enrollSoftwareDevice(t *testing.T, ca *CA, model, serial string) (*softwareTCGCSR, *CertificateRequest, []byte, []byte) {
	t.Helper()
	device := buildSoftwareTCGCSR(t, model, serial)

	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = model + "-" + serial

	iakDER, idevidDER, err := ca.SignTCGCSRIDevID(context.Background(), device.csr, request)
	if err != nil {
		t.Fatalf("SignTCGCSRIDevID() returned unexpected error: %v", err)
	}
	return device, request, iakDER, idevidDER
}

func parseDER(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// =============================================================================
// IAKCommonName
// =============================================================================

func TestIAKCommonName(t *testing.T) {
	tests := []struct {
		name   string
		model  string
		serial string
		want   string
	}{
		{"model and serial", "SuperMicro X10", "SN-371", "iak-SuperMicro X10-SN-371"},
		{"matches the enroll-01 idevid name with the prefix", "xkms-node", "SN-0001", IAKCommonNamePrefix + "xkms-node-SN-0001"},
		{"empty fields still yield a distinct name", "", "", "iak--"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IAKCommonName(tt.model, tt.serial); got != tt.want {
				t.Errorf("IAKCommonName(%q, %q) = %q, want %q", tt.model, tt.serial, got, tt.want)
			}
		})
	}
}

func TestIAKCommonName_NeverEqualsIDevIDName(t *testing.T) {
	model, serial := softwareCSRModel, softwareCSRSerial
	idevid := model + "-" + serial
	if IAKCommonName(model, serial) == idevid {
		t.Fatalf("IAK name %q collides with IDevID name %q", IAKCommonName(model, serial), idevid)
	}
	if !strings.HasPrefix(IAKCommonName(model, serial), IAKCommonNamePrefix) {
		t.Fatalf("IAK name %q lacks prefix %q", IAKCommonName(model, serial), IAKCommonNamePrefix)
	}
}

// =============================================================================
// SignTCGCSRIDevID storage
// =============================================================================

// TestSignTCGCSRIDevID_IAKRecordSurvivesIDevIDIssuance is the regression test
// for #371: after one enrollment the store holds two records, and the IAK is
// retrievable under its own name with the IAK public key inside.
func TestSignTCGCSRIDevID_IAKRecordSurvivesIDevIDIssuance(t *testing.T) {
	ca := createTestCAForTCG(t)
	device, request, iakDER, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	stored, err := ca.certStore.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates() error: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("store holds %d certificate(s) after enrollment, want 2 (IAK and IDevID)", len(stored))
	}

	iakCert, err := ca.certStore.GetCertificate(IAKCommonName(softwareCSRModel, softwareCSRSerial))
	if err != nil {
		t.Fatalf("IAK record missing from the store: %v", err)
	}
	if iakCert.Subject.CommonName != "iak-SuperMicro X10-SN-371" {
		t.Errorf("IAK Subject.CommonName = %q, want %q", iakCert.Subject.CommonName, "iak-SuperMicro X10-SN-371")
	}
	iakPub, ok := iakCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !iakPub.Equal(&device.iakKey.PublicKey) {
		t.Error("stored IAK record does not certify the IAK public key")
	}
	if string(iakCert.Raw) != string(iakDER) {
		t.Error("stored IAK record differs from the IAK DER returned to the caller")
	}
	if !hasExtensionOID(iakCert, OIDTCGKpAIKCertificate) {
		t.Error("IAK record lost its TCG AIK certificate extension")
	}

	idevidCert, err := ca.certStore.GetCertificate(request.Subject.CommonName)
	if err != nil {
		t.Fatalf("IDevID record missing from the store: %v", err)
	}
	idevidPub, ok := idevidCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !idevidPub.Equal(&device.idevidKey.PublicKey) {
		t.Error("stored IDevID record does not certify the IDevID public key")
	}
	if string(idevidCert.Raw) != string(idevidDER) {
		t.Error("stored IDevID record differs from the IDevID DER returned to the caller")
	}
	if iakCert.SerialNumber.Cmp(idevidCert.SerialNumber) == 0 {
		t.Error("IAK and IDevID share a serial number")
	}
}

// TestSignTCGCSRIDevID_IDevIDCommonNameUnchanged pins the IDevID subject:
// consumers look devices up under the request common name ("<model>-<serial>"
// on the enroll-01 path) and must not be affected by the IAK rename.
func TestSignTCGCSRIDevID_IDevIDCommonNameUnchanged(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, request, _, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	idevidCert := parseDER(t, idevidDER)
	if idevidCert.Subject.CommonName != request.Subject.CommonName {
		t.Fatalf("IDevID Subject.CommonName = %q, want the request common name %q",
			idevidCert.Subject.CommonName, request.Subject.CommonName)
	}
	if idevidCert.Subject.CommonName != "SuperMicro X10-SN-371" {
		t.Fatalf("IDevID Subject.CommonName = %q, want %q", idevidCert.Subject.CommonName, "SuperMicro X10-SN-371")
	}
	if strings.HasPrefix(idevidCert.Subject.CommonName, IAKCommonNamePrefix) {
		t.Fatalf("IDevID subject %q carries the IAK prefix", idevidCert.Subject.CommonName)
	}
	if _, err := ca.certStore.GetCertificate(request.Subject.CommonName); err != nil {
		t.Fatalf("IDevID not retrievable under the request common name: %v", err)
	}
}

// TestSignTCGCSRIDevID_IAKKeepsRequestSubjectApartFromCN checks that only the
// common name of the IAK subject changes; the rest of the caller's subject
// (organization, country) is carried through as before.
func TestSignTCGCSRIDevID_IAKKeepsRequestSubjectApartFromCN(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, request, iakDER, _ := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	iakCert := parseDER(t, iakDER)
	if len(iakCert.Subject.Organization) != 1 || iakCert.Subject.Organization[0] != request.Subject.Organization {
		t.Errorf("IAK Subject.Organization = %v, want [%q]", iakCert.Subject.Organization, request.Subject.Organization)
	}
	if len(iakCert.Subject.Country) != 1 || iakCert.Subject.Country[0] != request.Subject.Country {
		t.Errorf("IAK Subject.Country = %v, want [%q]", iakCert.Subject.Country, request.Subject.Country)
	}
	if iakCert.Subject.CommonName == request.Subject.CommonName {
		t.Errorf("IAK Subject.CommonName %q equals the request common name", iakCert.Subject.CommonName)
	}
}

// TestSignTCGCSRIDevID_TwoDevicesTwoIAKRecords: distinct devices get distinct
// IAK records, since the IAK name is derived from the device identity.
func TestSignTCGCSRIDevID_TwoDevicesTwoIAKRecords(t *testing.T) {
	ca := createTestCAForTCG(t)
	enrollSoftwareDevice(t, ca, softwareCSRModel, "SN-A")
	enrollSoftwareDevice(t, ca, softwareCSRModel, "SN-B")

	stored, err := ca.certStore.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates() error: %v", err)
	}
	if len(stored) != 4 {
		t.Fatalf("store holds %d certificate(s) after two enrollments, want 4", len(stored))
	}
	for _, serial := range []string{"SN-A", "SN-B"} {
		if _, err := ca.certStore.GetCertificate(IAKCommonName(softwareCSRModel, serial)); err != nil {
			t.Errorf("IAK record for serial %q missing: %v", serial, err)
		}
	}
}

func TestSignTCGCSRIDevID_IAKStoreErrorFailsIssuance(t *testing.T) {
	ca := createTestCAForTCG(t)
	store := ca.certStore.(*mockCertStoreForTCG)
	store.storeError = errors.New("disk full")

	device := buildSoftwareTCGCSR(t, softwareCSRModel, softwareCSRSerial)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), device.csr, request)
	if !errors.Is(err, ErrTCGCertIssuanceFailed) {
		t.Fatalf("error = %v, want ErrTCGCertIssuanceFailed", err)
	}
	var detail *errs.Detail
	if !errors.As(err, &detail) || !strings.Contains(detail.Detail, "store iak") {
		t.Fatalf("error detail = %v, want the IAK store failure named", err)
	}
}

// =============================================================================
// IAKCertificate
// =============================================================================

func TestIAKCertificate_ReturnsEnrolledIAK(t *testing.T) {
	ca := createTestCAForTCG(t)
	device, _, iakDER, _ := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	cert, err := ca.IAKCertificate(context.Background(), softwareCSRModel, softwareCSRSerial)
	if err != nil {
		t.Fatalf("IAKCertificate() error: %v", err)
	}
	if string(cert.Raw) != string(iakDER) {
		t.Error("IAKCertificate() returned a certificate other than the one issued at enrollment")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&device.iakKey.PublicKey) {
		t.Error("IAKCertificate() does not certify the IAK public key")
	}
}

func TestIAKCertificate_DoesNotReturnTheIDevID(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, _, _, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	cert, err := ca.IAKCertificate(context.Background(), softwareCSRModel, softwareCSRSerial)
	if err != nil {
		t.Fatalf("IAKCertificate() error: %v", err)
	}
	if string(cert.Raw) == string(idevidDER) {
		t.Fatal("IAKCertificate() returned the IDevID certificate")
	}
}

func TestIAKCertificate_NotFound(t *testing.T) {
	ca := createTestCAForTCG(t)

	_, err := ca.IAKCertificate(context.Background(), softwareCSRModel, "never-enrolled")
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("error = %v, want ErrCertificateNotFound", err)
	}
	var detail *errs.Detail
	if !errors.As(err, &detail) || detail.Detail != IAKCommonName(softwareCSRModel, "never-enrolled") {
		t.Fatalf("error detail = %v, want the looked-up IAK name", err)
	}
}

func TestIAKCertificate_NotInitialized(t *testing.T) {
	ca := createUninitializedTestCA(t)

	_, err := ca.IAKCertificate(context.Background(), softwareCSRModel, softwareCSRSerial)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

func TestIAKCertificate_NoCertStore(t *testing.T) {
	ca := createTestCAForTCG(t)
	ca.certStore = nil

	_, err := ca.IAKCertificate(context.Background(), softwareCSRModel, softwareCSRSerial)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("error = %v, want ErrCertificateNotFound", err)
	}
}

func TestIAKCertificate_SatisfiesReader(t *testing.T) {
	var reader IAKCertificateReader = createTestCAForTCG(t)
	if _, err := reader.IAKCertificate(context.Background(), softwareCSRModel, softwareCSRSerial); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("error = %v, want ErrCertificateNotFound through the interface", err)
	}
}
