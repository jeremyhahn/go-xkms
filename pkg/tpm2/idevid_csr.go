package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"fmt"
	"math"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// TPM_RC_SIGNATURE (parameter 2): the signature is not valid
	ErrInvalidSignature = errors.New("tpm: invalid signature")
)

// MaxIDevIDCSRSize is the largest packed TCG-CSR-IDEVID UnmarshalIDevIDCSR
// accepts. The TCG DevID specification does not bound the structure; the
// largest field in practice is the boot event log, tens of kilobytes on
// real firmware, so 1 MiB leaves ample headroom while keeping a hostile
// message from dictating the parser's memory use.
const MaxIDevIDCSRSize = 1 << 20

// IDevIDCSRTooLargeError is returned when a packed TCG-CSR-IDEVID exceeds
// MaxIDevIDCSRSize.
type IDevIDCSRTooLargeError struct {
	Size int
	Max  int
}

func (e *IDevIDCSRTooLargeError) Error() string {
	return fmt.Sprintf("tpm: TCG-CSR-IDEVID is %d bytes, larger than the %d-byte maximum", e.Size, e.Max)
}

// IDevIDCSRFieldSizeError is returned when a TCG-CSR-IDEVID length field
// declares more bytes than remain in the message. It wraps
// io.ErrUnexpectedEOF: the message is truncated relative to its own
// declarations.
type IDevIDCSRFieldSizeError struct {
	Field     string
	Declared  uint32
	Remaining int
}

func (e *IDevIDCSRFieldSizeError) Error() string {
	return fmt.Sprintf("tpm: TCG-CSR-IDEVID field %s declares %d bytes but only %d remain", e.Field, e.Declared, e.Remaining)
}

// Unwrap returns io.ErrUnexpectedEOF.
func (e *IDevIDCSRFieldSizeError) Unwrap() error { return io.ErrUnexpectedEOF }

// Creates a TCG_CSR_IDEVID structure in alignment with the TCG
// TPM 2.0 Keys for Device Identity and Attestation - Section 13.1 -
// TCG-CSR-IDEVID.
func (tpm *TPM2) CreateTCG_CSR_IDEVID(
	ekCert *x509.Certificate,
	akAttrs *types.KeyAttributes,
	idevidAttrs *types.KeyAttributes) (TCG_CSR_IDEVID, error) {

	var signerAttrs *types.KeyAttributes

	enrollmentStrategy := ParseIdentityProvisioningStrategy(tpm.config.IdentityProvisioningStrategy)

	switch enrollmentStrategy {
	case EnrollmentStrategyIAK:
		signerAttrs = akAttrs
	case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
		signerAttrs = idevidAttrs
	default:
		return TCG_CSR_IDEVID{}, ErrInvalidEnrollmentStrategy
	}

	tcgContent := &TCG_IDEVID_CONTENT{}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs, signerAttrs)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	// Size the TCG_IDEVID_CONTENT structure for the CSR's Contents header.
	//
	// Per TCG "TPM 2.0 Keys for Device Identity and Attestation" section 13.1,
	// Contents is the size of the TCG_IDEVID_CONTENT structure, and a padded
	// structure is a multiple of 16 bytes. Three separate errors used to make
	// this wrong, and only xkms's own tolerance hid them: UnmarshalIDevIDCSR
	// ignores Contents and re-reads the individual length fields, so a
	// spec-conformant third-party CA slicing the message by Contents was the
	// only party that ever saw the damage.
	//
	//  1. The payload sum omitted SigningPubSZ, SgnCertifyInfoSZ and
	//     SgnCertifyInfoSignatureSZ, and counted 10 header fields where the
	//     structure has 16 -- together understating a real CSR by ~709 bytes.
	//  2. The pad was contents%16, the remainder, where alignment needs
	//     (16 - contents%16) % 16. Padded structures came out unaligned.
	//  3. contents was assigned only inside the padding branch, so with
	//     padding disabled the header advertised a size of zero.
	//
	// Accumulate in uint64 so a hostile or corrupt set of lengths reports an
	// overflow instead of wrapping into a plausible small size.
	const idevidContentSizeFields = 16
	payloadSz := uint64(content.ProdModelSz) + uint64(content.ProdSerialSz) +
		uint64(content.ProdCaDataSz) + uint64(content.BootEvntLogSz) +
		uint64(content.EkCertSZ) + uint64(content.AttestPubSZ) +
		uint64(content.AtCreateTktSZ) + uint64(content.AtCertifyInfoSZ) +
		uint64(content.AtCertifyInfoSignatureSZ) + uint64(content.SigningPubSZ) +
		uint64(content.SgnCertifyInfoSZ) + uint64(content.SgnCertifyInfoSignatureSZ)

	baseSz := payloadSz + uint64(idevidContentSizeFields*4)

	var padding []byte
	var padSz uint32
	if tpm.config.IDevID.Pad {
		// Section 13.1: "Payload is followed by padSz bytes of random data
		// here to make the structure size a multiple of 16 bytes." The pad
		// is drawn from the TPM's RNG; a fixed filler byte was a departure.
		padSz = uint32((TCGCSRAlignment - baseSz%TCGCSRAlignment) % TCGCSRAlignment) // #nosec G115 -- result is < 16
		if padSz > 0 {
			padding, err = tpm.RandomBytes(int(padSz))
			if err != nil {
				return TCG_CSR_IDEVID{}, &errs.Joined{Lead: ErrTCGCSRPad, Cause: err}
			}
		}
	}

	totalSz := baseSz + uint64(padSz)
	if totalSz > math.MaxUint32 {
		return TCG_CSR_IDEVID{}, &errs.Message{
			Msg: fmt.Sprintf("TCG_IDEVID_CONTENT size overflows uint32: %d", totalSz)}
	}
	contents := uint32(totalSz) // #nosec G115 -- bounds checked above

	binary.BigEndian.PutUint32(tcgContent.StructVer[:], TCGIDevIDContentStructVer)
	binary.BigEndian.PutUint32(tcgContent.HashAlgoId[:], content.HashAlgoId)
	binary.BigEndian.PutUint32(tcgContent.HashSz[:], content.HashSz)

	// Hash of all that follows is placed here
	binary.BigEndian.PutUint32(tcgContent.ProdModelSz[:], content.ProdModelSz)
	binary.BigEndian.PutUint32(tcgContent.ProdSerialSz[:], content.ProdSerialSz)
	binary.BigEndian.PutUint32(tcgContent.ProdCaDataSz[:], content.ProdCaDataSz)
	binary.BigEndian.PutUint32(tcgContent.BootEvntLogSz[:], content.BootEvntLogSz)
	binary.BigEndian.PutUint32(tcgContent.EkCertSZ[:], content.EkCertSZ)
	binary.BigEndian.PutUint32(tcgContent.AttestPubSZ[:], content.AttestPubSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCreateTktSZ[:], content.AtCreateTktSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCertifyInfoSZ[:], content.AtCertifyInfoSZ)
	binary.BigEndian.PutUint32(tcgContent.AtCertifyInfoSignatureSZ[:], content.AtCertifyInfoSignatureSZ)
	binary.BigEndian.PutUint32(tcgContent.SigningPubSZ[:], content.SigningPubSZ)
	binary.BigEndian.PutUint32(tcgContent.SgnCertifyInfoSZ[:], content.SgnCertifyInfoSZ)
	binary.BigEndian.PutUint32(tcgContent.SgnCertifyInfoSignatureSZ[:], content.SgnCertifyInfoSignatureSZ)
	binary.BigEndian.PutUint32(tcgContent.PadSz[:], padSz)

	tcgContent.ProdModel = make([]byte, content.ProdModelSz)
	copy(tcgContent.ProdModel, content.ProdModel)

	tcgContent.ProdSerial = make([]byte, content.ProdSerialSz)
	copy(tcgContent.ProdSerial, content.ProdSerial)

	tcgContent.ProdCaData = make([]byte, content.ProdCaDataSz)
	copy(tcgContent.ProdCaData, content.ProdCaData)

	tcgContent.BootEvntLog = make([]byte, content.BootEvntLogSz)
	copy(tcgContent.BootEvntLog, content.BootEvntLog)

	tcgContent.EkCert = make([]byte, content.EkCertSZ)
	copy(tcgContent.EkCert, content.EkCert)

	tcgContent.AttestPub = make([]byte, content.AttestPubSZ)
	copy(tcgContent.AttestPub, content.AttestPub)

	tcgContent.AtCreateTkt = make([]byte, content.AtCreateTktSZ)
	copy(tcgContent.AtCreateTkt, content.AtCreateTkt)

	tcgContent.AtCertifyInfo = make([]byte, content.AtCertifyInfoSZ)
	copy(tcgContent.AtCertifyInfo, content.AtCertifyInfo)

	tcgContent.AtCertifyInfoSig = make([]byte, content.AtCertifyInfoSignatureSZ)
	copy(tcgContent.AtCertifyInfoSig, content.AtCertifyInfoSig)

	tcgContent.SigningPub = make([]byte, content.SigningPubSZ)
	copy(tcgContent.SigningPub, content.SigningPub)

	tcgContent.SgnCertifyInfo = make([]byte, content.SgnCertifyInfoSZ)
	copy(tcgContent.SgnCertifyInfo, content.SgnCertifyInfo)

	tcgContent.SgnCertifyInfoSig = make([]byte, content.SgnCertifyInfoSignatureSZ)
	copy(tcgContent.SgnCertifyInfoSig, content.SgnCertifyInfoSig)

	tcgContent.Pad = make([]byte, padSz)
	copy(tcgContent.Pad, padding)

	packedContents, err := PackIDevIDContent(tcgContent)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	digest, validationDigest, err := tpm.HashSequence(signerAttrs, packedContents)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	signature, err := tpm.SignValidate(signerAttrs, digest, validationDigest)
	if err != nil {
		return TCG_CSR_IDEVID{}, err
	}

	// Section 13.1: TCG_CSR_IDEVID.structVer "Version 1.0 = 0x01000100"; the
	// leading 0x01 is what tells an IDevID CSR from an LDevID CSR (0x02). The
	// content structure's own version, 0x00000100, was previously written
	// here too, so the outer header announced no CSR type at all.
	tcgCSR := TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(tcgCSR.StructVer[:], TCGCSRIDevIDStructVer)
	binary.BigEndian.PutUint32(tcgCSR.Contents[:], contents)
	if len(signature) > math.MaxUint32 {
		return TCG_CSR_IDEVID{}, &errs.Message{Msg: fmt.Sprintf("signature too large: %d", len(signature))}
	}
	binary.BigEndian.PutUint32(tcgCSR.SigSz[:], uint32(len(signature))) // #nosec G115 -- CSR signature size
	tcgCSR.CsrContents = *tcgContent
	tcgCSR.Signature = signature

	return tcgCSR, nil
}

// Create the TCG_CSR_IDEVID content structure.
//
// signerAttrs is the key that signs the CSR -- the IAK under
// EnrollmentStrategyIAK, the IDevID under the single-pass strategy. Section
// 13.1 defines hashAlgoId as the "TCG algorithm identifier for CSR hash" and
// hashSz as the "Size, in bytes, of hash used", so both describe the signer's
// hash: that is the algorithm HashSequence digests the contents with and the
// one the CA re-hashes with to verify the signature. They used to be taken
// from two different keys (the IAK's algorithm, the IDevID's size), which
// only agreed while both keys happened to use the same hash.
func (tpm *TPM2) createIDevIDContent(
	ekCert *x509.Certificate,
	akAttrs *types.KeyAttributes,
	idevidAttrs *types.KeyAttributes,
	signerAttrs *types.KeyAttributes) (*UNPACKED_TCG_IDEVID_CONTENT, error) {

	if ekCert == nil {
		return nil, ErrInvalidEKCert
	}
	// Under EnrollmentStrategyIAK there is no IDevID key, and
	// IDevIDAttributes() reports that with ErrIDevIDConfigNil. Passing that nil
	// through reached the idevidAttrs.Hash dereference below and panicked;
	// library code must return the error instead.
	if idevidAttrs == nil {
		return nil, ErrIDevIDConfigNil
	}
	if akAttrs == nil {
		return nil, ErrIAKConfigNil
	}
	if signerAttrs == nil || signerAttrs.TPMAttributes == nil {
		return nil, ErrInvalidKeyAttributes
	}
	ekCertRaw := ekCert.Raw

	csrHash, err := signerAttrs.TPMAttributes.HashAlg.Hash()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrInvalidHashFunction, Cause: err}
	}
	hashSz, err := ParseHashSize(csrHash)
	if err != nil {
		return nil, err
	}

	bootEventLog, err := tpm.EventLog()
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			// /sys/kernel/security/tpm0/binary_bios_measurements: no such file or directory
			// or permission denied
			// return nil, ErrMissingMeasurementLog

			// Some embedded systems may not have a measurement log or there may be a permission
			// problem. Log the warning and carry on...
			tpm.logger.Warn(ErrMissingMeasurementLog.Error())
		} else {
			return nil, err
		}
	}

	// Generate attestation data (Quote + PCRs) for ProdCaData
	// This carries the device's attestation state to the CA during enrollment
	//
	// Section 13.1 allows the field to be absent (prodCaDataSz 0), and
	// createProdCaData reports absence -- no transport to quote over -- as a
	// nil payload without error. A quote the TPM refused is not absence; the
	// CSR is not emitted with the attestation silently dropped.
	prodCaData, prodCaDataSz, err := tpm.createProdCaData()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGCSRAttestation, Cause: err}
	}

	akBPublic := akAttrs.TPMAttributes.BPublic
	akPublicBytes := akBPublic.Bytes()
	atCreateTktBytes := akAttrs.TPMAttributes.CreationTicketDigest
	akCertifyInfoBytes := akAttrs.TPMAttributes.CertifyInfo
	akCertifyInfoSignature := akAttrs.TPMAttributes.Signature

	sgnCertifyInfoBytes := idevidAttrs.TPMAttributes.CertifyInfo
	idevidBPublic := idevidAttrs.TPMAttributes.BPublic
	signingPubBytes := idevidBPublic.Bytes()
	sgnCertifyInfoSig := idevidAttrs.TPMAttributes.Signature

	// Resolve platform attributes with config-first-then-SMBIOS fallback
	platformAttrs := ResolvePlatformAttributes(tpm.config.IDevID)

	// Validate all CSR field sizes before building the struct
	csrFields := []struct {
		name string
		size int
	}{
		{"model", len(platformAttrs.Model)},
		{"serial", len(platformAttrs.Serial)},
		{"bootEventLog", len(bootEventLog)},
		{"ekCert.Raw", len(ekCertRaw)},
		{"akPublicBytes", len(akPublicBytes)},
		{"atCreateTktBytes", len(atCreateTktBytes)},
		{"akCertifyInfoBytes", len(akCertifyInfoBytes)},
		{"akCertifyInfoSignature", len(akCertifyInfoSignature)},
		{"signingPubBytes", len(signingPubBytes)},
		{"sgnCertifyInfoBytes", len(sgnCertifyInfoBytes)},
		{"sgnCertifyInfoSig", len(sgnCertifyInfoSig)},
	}
	for _, f := range csrFields {
		if f.size > math.MaxUint32 {
			return nil, &errs.Detail{Err: ErrCSRFieldTooLarge, Detail: fmt.Sprintf("%s (%d bytes)", f.name, f.size)}
		}
	}

	// Build an unpacked TCG_IDEVID_CONTENT structure that omits
	// the HashSz, PadSz, and Pad fields. They will be populated
	// during the packing operation.
	return &UNPACKED_TCG_IDEVID_CONTENT{
		StructVer:                 TCGIDevIDContentStructVer,
		HashAlgoId:                uint32(signerAttrs.TPMAttributes.HashAlg),
		HashSz:                    hashSz,
		ProdModelSz:               uint32(len(platformAttrs.Model)),  // #nosec G115 -- Bounds checked above
		ProdSerialSz:              uint32(len(platformAttrs.Serial)), // #nosec G115 -- Bounds checked above
		ProdCaDataSz:              prodCaDataSz,
		BootEvntLogSz:             uint32(len(bootEventLog)),           // #nosec G115 -- Bounds checked above
		EkCertSZ:                  uint32(len(ekCertRaw)),              // #nosec G115 -- Bounds checked above
		AttestPubSZ:               uint32(len(akPublicBytes)),          // #nosec G115 -- Bounds checked above
		AtCreateTktSZ:             uint32(len(atCreateTktBytes)),       // #nosec G115 -- Bounds checked above
		AtCertifyInfoSZ:           uint32(len(akCertifyInfoBytes)),     // #nosec G115 -- Bounds checked above
		AtCertifyInfoSignatureSZ:  uint32(len(akCertifyInfoSignature)), // #nosec G115 -- Bounds checked above
		SigningPubSZ:              uint32(len(signingPubBytes)),        // #nosec G115 -- Bounds checked above
		SgnCertifyInfoSZ:          uint32(len(sgnCertifyInfoBytes)),    // #nosec G115 -- Bounds checked above
		SgnCertifyInfoSignatureSZ: uint32(len(sgnCertifyInfoSig)),      // #nosec G115 -- Bounds checked above
		// Payload bytes begin here.
		// All payloads are included as byte arrays (no delimiters)
		// Payload is followed by padSz bytes of random data here to make
		// the structure size a multiple of 16 bytes.
		ProdModel:         []byte(platformAttrs.Model),
		ProdSerial:        []byte(platformAttrs.Serial),
		ProdCaData:        prodCaData,
		BootEvntLog:       bootEventLog,
		EkCert:            ekCertRaw,
		AttestPub:         akPublicBytes,
		AtCreateTkt:       atCreateTktBytes,
		AtCertifyInfo:     akCertifyInfoBytes,
		AtCertifyInfoSig:  akCertifyInfoSignature,
		SigningPub:        signingPubBytes,
		SgnCertifyInfo:    sgnCertifyInfoBytes,
		SgnCertifyInfoSig: sgnCertifyInfoSig,
	}, nil
}

// createProdCaData generates attestation data (TPM Quote + PCRs) for inclusion
// in the TCG-CSR-IDEVID ProdCaData field. Per TCG TPM 2.0 Keys for Device Identity
// and Attestation specification, ProdCaData is used for CA-specific required data.
//
// This enables the CA to receive and store the device's initial attestation state
// upon successful IDevID issuance, eliminating the need for local attestation
// on the client after enrollment.
//
// Returns the packed ProdCaData bytes, its size, and any error.
func (tpm *TPM2) createProdCaData() ([]byte, uint32, error) {
	// Gate on the transport, not on tpm.device.
	//
	// tpm.device holds an *os.File and is populated only by the raw
	// os.OpenFile branch of NewTPM2 (tpm.go). A unix-socket TPM (".sock"), a
	// TCP/mssim TPM, the in-process simulator and an injected transport all
	// leave it nil while being perfectly capable of producing a quote, so this
	// guard used to drop the attestation from every enrollment CSR on those
	// deployments -- no quote, no PCRs -- announced by nothing louder than a
	// Debug line. A CA that expects to verify platform state received a CSR
	// that silently carried none.
	//
	// tpm.transport is assigned on every path in NewTPM2 and is what the
	// commands below actually travel over, so it is the honest predicate.
	if tpm.transport == nil {
		tpm.logger.Debug("tpm: no TPM transport available, skipping ProdCaData creation")
		return nil, 0, nil
	}

	// Use GoldenPCRs from config, or the platform PCR set if not configured
	pcrs := tpm.config.GoldenPCRs
	if len(pcrs) == 0 {
		pcrs = tpm.config.PlatformPCRs
	}

	// Generate a random nonce for the quote
	nonce, err := tpm.Random()
	if err != nil {
		return nil, 0, &errs.Wrapped{Msg: "failed to generate nonce for ProdCaData", Err: err}
	}

	tpm.logger.Info("creating ProdCaData attestation", slog.Any("pcrs", pcrs))

	// Perform TPM Quote over the configured PCRs
	quote, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		return nil, 0, &errs.Wrapped{Msg: "failed to create quote for ProdCaData", Err: err}
	}

	// Create ProdCaData from the quote
	prodCaData, err := NewProdCaData(&quote)
	if err != nil {
		return nil, 0, &errs.Wrapped{Msg: "failed to create ProdCaData", Err: err}
	}

	// Pack the ProdCaData
	packedData, err := PackProdCaData(prodCaData)
	if err != nil {
		return nil, 0, &errs.Wrapped{Msg: "failed to pack ProdCaData", Err: err}
	}

	if len(packedData) > math.MaxUint32 {
		return nil, 0, ErrProdCaDataTooLarge
	}

	tpm.logger.Debug("ProdCaData created",
		slog.Int("total_bytes", len(packedData)),
		slog.Int("quoted_bytes", len(quote.Quoted)),
		slog.Int("signature_bytes", len(quote.Signature)),
		slog.Int("nonce_bytes", len(quote.Nonce)),
		slog.Int("pcr_count", len(quote.PCRs)))

	return packedData, uint32(len(packedData)), nil // #nosec G115 -- validated above
}

// Packs the TCG-CSR-IDEVID into a big endian binary byte array
func PackIDevIDCSR(csr *TCG_CSR_IDEVID) ([]byte, error) {

	var csrBuf bytes.Buffer

	err := binary.Write(&csrBuf, binary.BigEndian, csr.StructVer)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.Contents)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.SigSz)
	if err != nil {
		return nil, err
	}

	csrContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&csrBuf, binary.BigEndian, csrContents)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csrBuf, binary.BigEndian, csr.Signature)
	if err != nil {
		return nil, err
	}

	return csrBuf.Bytes(), nil
}

// Packs the TCG_IDEVID_CONTENT structure into a big endian byte array
func PackIDevIDContent(content *TCG_IDEVID_CONTENT) ([]byte, error) {

	var csr bytes.Buffer
	err := binary.Write(&csr, binary.BigEndian, content.StructVer)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.HashAlgoId)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.HashSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdModelSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdSerialSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdCaDataSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.BootEvntLogSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.EkCertSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AttestPubSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCreateTktSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SigningPubSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.PadSz)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdModel)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdSerial)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.ProdCaData)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.BootEvntLog)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.EkCert)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AttestPub)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCreateTkt)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfo)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.AtCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SigningPub)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfo)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.SgnCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&csr, binary.BigEndian, content.Pad)
	if err != nil {
		return nil, err
	}

	return csr.Bytes(), nil
}

// Unmarshalls a fixed size big endian byte array into a uint32
func bytesToUint32(b [4]byte) uint32 {
	return binary.BigEndian.Uint32(b[:])
}

// UnmarshalIDevIDCSR parses a packed, big-endian TCG_CSR_IDEVID.
//
// The input is attacker-supplied (an enroll-01 challenge response, an ACME
// finalize request), so it is bounded before anything is allocated: input
// larger than MaxIDevIDCSRSize is refused with *IDevIDCSRTooLargeError, and
// every length field is checked against the bytes actually remaining before
// its buffer is made (see readSizedField), so a declared length can never
// allocate more than the message carries.
func UnmarshalIDevIDCSR(csrBytes []byte) (*TCG_CSR_IDEVID, error) {
	if len(csrBytes) > MaxIDevIDCSRSize {
		return nil, &IDevIDCSRTooLargeError{Size: len(csrBytes), Max: MaxIDevIDCSRSize}
	}

	reader := bytes.NewReader(csrBytes)

	var structVer [4]byte
	if err := binary.Read(reader, binary.BigEndian, &structVer); err != nil {
		return nil, err
	}

	var contents [4]byte
	if err := binary.Read(reader, binary.BigEndian, &contents); err != nil {
		return nil, err
	}

	var sigSz [4]byte
	if err := binary.Read(reader, binary.BigEndian, &sigSz); err != nil {
		return nil, err
	}

	csr := TCG_CSR_IDEVID{
		StructVer: structVer,
		Contents:  contents,
		SigSz:     sigSz,
	}

	csrContents, err := UnpackIDevIDContent(reader)
	if err != nil {
		return nil, err
	}
	csr.CsrContents = *csrContents

	csr.Signature, err = readSizedField(reader, "Signature", sigSz)
	if err != nil {
		return nil, err
	}

	return &csr, nil
}

// UnpackIDevIDContent parses a TCG_IDEVID_CONTENT from reader. Every
// variable-length field is bounded by the bytes remaining in reader before
// its buffer is allocated; a field declaring more than remains is refused
// with *IDevIDCSRFieldSizeError, which wraps io.ErrUnexpectedEOF.
func UnpackIDevIDContent(reader *bytes.Reader) (*TCG_IDEVID_CONTENT, error) {
	if reader.Len() > MaxIDevIDCSRSize {
		return nil, &IDevIDCSRTooLargeError{Size: reader.Len(), Max: MaxIDevIDCSRSize}
	}

	content := &TCG_IDEVID_CONTENT{}

	if err := binary.Read(reader, binary.BigEndian, &content.StructVer); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.HashAlgoId); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.HashSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdModelSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdSerialSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.ProdCaDataSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.BootEvntLogSz); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.EkCertSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AttestPubSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCreateTktSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCertifyInfoSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.AtCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SigningPubSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SgnCertifyInfoSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.SgnCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &content.PadSz); err != nil {
		return nil, err
	}

	var err error
	if content.ProdModel, err = readSizedField(reader, "ProdModel", content.ProdModelSz); err != nil {
		return nil, err
	}
	if content.ProdSerial, err = readSizedField(reader, "ProdSerial", content.ProdSerialSz); err != nil {
		return nil, err
	}
	if content.ProdCaData, err = readSizedField(reader, "ProdCaData", content.ProdCaDataSz); err != nil {
		return nil, err
	}
	if content.BootEvntLog, err = readSizedField(reader, "BootEvntLog", content.BootEvntLogSz); err != nil {
		return nil, err
	}
	if content.EkCert, err = readSizedField(reader, "EkCert", content.EkCertSZ); err != nil {
		return nil, err
	}
	if content.AttestPub, err = readSizedField(reader, "AttestPub", content.AttestPubSZ); err != nil {
		return nil, err
	}
	if content.AtCreateTkt, err = readSizedField(reader, "AtCreateTkt", content.AtCreateTktSZ); err != nil {
		return nil, err
	}
	if content.AtCertifyInfo, err = readSizedField(reader, "AtCertifyInfo", content.AtCertifyInfoSZ); err != nil {
		return nil, err
	}
	if content.AtCertifyInfoSig, err = readSizedField(reader, "AtCertifyInfoSig", content.AtCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}
	if content.SigningPub, err = readSizedField(reader, "SigningPub", content.SigningPubSZ); err != nil {
		return nil, err
	}
	if content.SgnCertifyInfo, err = readSizedField(reader, "SgnCertifyInfo", content.SgnCertifyInfoSZ); err != nil {
		return nil, err
	}
	if content.SgnCertifyInfoSig, err = readSizedField(reader, "SgnCertifyInfoSig", content.SgnCertifyInfoSignatureSZ); err != nil {
		return nil, err
	}
	if content.Pad, err = readSizedField(reader, "Pad", content.PadSz); err != nil {
		return nil, err
	}

	return content, nil
}

// readSizedField reads a field whose big-endian length was declared earlier
// in the same message. The declared length is checked against the bytes
// remaining in reader BEFORE the buffer is made: a 4-byte length field
// could otherwise ask for 4 GiB, and a TCG-CSR-IDEVID carries fifteen of
// them.
func readSizedField(reader *bytes.Reader, field string, size [4]byte) ([]byte, error) {
	declared := bytesToUint32(size)
	if int64(declared) > int64(reader.Len()) {
		return nil, &IDevIDCSRFieldSizeError{Field: field, Declared: declared, Remaining: reader.Len()}
	}
	buf := make([]byte, declared)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// copySizedField returns a copy of the first size bytes of src. size comes
// from a TCG_CSR_IDEVID size field and src from the field it describes; the
// two are independent in the struct, so a size larger than src is
// corruption and is refused with store.ErrCorruptCopy before the buffer is
// made, never zero-padded and never allowed to drive the allocation.
func copySizedField(size uint32, src []byte) ([]byte, error) {
	if uint64(size) > uint64(len(src)) {
		return nil, store.ErrCorruptCopy
	}
	dst := make([]byte, size)
	copy(dst, src)
	return dst, nil
}

// Unpacks a TCG_CSR_IDEVID big endian byte array
func UnpackIDevIDCSR(
	tcgCSRIDevID *TCG_CSR_IDEVID) (*UNPACKED_TCG_CSR_IDEVID, error) {

	tcgCSR := UNPACKED_TCG_CSR_IDEVID{}

	reader := bytes.NewReader(tcgCSRIDevID.StructVer[:])
	err := binary.Read(reader, binary.BigEndian, &tcgCSR.StructVer)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.Contents[:])
	err = binary.Read(reader, binary.BigEndian, &tcgCSR.Contents)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.SigSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgCSR.SigSz)
	if err != nil {
		return nil, err
	}

	tcgCSR.Signature, err = copySizedField(tcgCSR.SigSz, tcgCSRIDevID.Signature)
	if err != nil {
		return nil, err
	}

	tcgContents := UNPACKED_TCG_IDEVID_CONTENT{}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.StructVer[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.StructVer)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.HashAlgoId[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.HashAlgoId)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.HashSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.HashSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdModelSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdModelSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdSerialSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdSerialSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.ProdCaDataSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.ProdCaDataSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.BootEvntLogSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.BootEvntLogSz)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.EkCertSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.EkCertSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AttestPubSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AttestPubSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCreateTktSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCreateTktSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCertifyInfoSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.AtCertifyInfoSignatureSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.AtCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SigningPubSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SigningPubSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SgnCertifyInfoSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SgnCertifyInfoSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.SgnCertifyInfoSignatureSZ[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.SgnCertifyInfoSignatureSZ)
	if err != nil {
		return nil, err
	}

	reader = bytes.NewReader(tcgCSRIDevID.CsrContents.PadSz[:])
	err = binary.Read(reader, binary.BigEndian, &tcgContents.PadSz)
	if err != nil {
		return nil, err
	}

	tcgContents.ProdModel, err = copySizedField(tcgContents.ProdModelSz, tcgCSRIDevID.CsrContents.ProdModel)
	if err != nil {
		return nil, err
	}

	tcgContents.ProdSerial, err = copySizedField(tcgContents.ProdSerialSz, tcgCSRIDevID.CsrContents.ProdSerial)
	if err != nil {
		return nil, err
	}

	tcgContents.ProdCaData, err = copySizedField(tcgContents.ProdCaDataSz, tcgCSRIDevID.CsrContents.ProdCaData)
	if err != nil {
		return nil, err
	}

	tcgContents.BootEvntLog, err = copySizedField(tcgContents.BootEvntLogSz, tcgCSRIDevID.CsrContents.BootEvntLog)
	if err != nil {
		return nil, err
	}

	tcgContents.EkCert, err = copySizedField(tcgContents.EkCertSZ, tcgCSRIDevID.CsrContents.EkCert)
	if err != nil {
		return nil, err
	}

	tcgContents.AttestPub, err = copySizedField(tcgContents.AttestPubSZ, tcgCSRIDevID.CsrContents.AttestPub)
	if err != nil {
		return nil, err
	}

	tcgContents.AtCreateTkt, err = copySizedField(tcgContents.AtCreateTktSZ, tcgCSRIDevID.CsrContents.AtCreateTkt)
	if err != nil {
		return nil, err
	}

	tcgContents.AtCertifyInfo, err = copySizedField(tcgContents.AtCertifyInfoSZ, tcgCSRIDevID.CsrContents.AtCertifyInfo)
	if err != nil {
		return nil, err
	}

	tcgContents.AtCertifyInfoSig, err = copySizedField(tcgContents.AtCertifyInfoSignatureSZ, tcgCSRIDevID.CsrContents.AtCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	tcgContents.SigningPub, err = copySizedField(tcgContents.SigningPubSZ, tcgCSRIDevID.CsrContents.SigningPub)
	if err != nil {
		return nil, err
	}

	tcgContents.SgnCertifyInfo, err = copySizedField(tcgContents.SgnCertifyInfoSZ, tcgCSRIDevID.CsrContents.SgnCertifyInfo)
	if err != nil {
		return nil, err
	}

	tcgContents.SgnCertifyInfoSig, err = copySizedField(tcgContents.SgnCertifyInfoSignatureSZ, tcgCSRIDevID.CsrContents.SgnCertifyInfoSig)
	if err != nil {
		return nil, err
	}

	tcgContents.Pad, err = copySizedField(tcgContents.PadSz, tcgCSRIDevID.CsrContents.Pad)
	if err != nil {
		return nil, err
	}

	tcgCSR.CsrContents = tcgContents

	return &tcgCSR, nil
}

// Verifies the TCG-CSR-IDEVID using the Identity Provisioning strategy defined in the
// platform configuration file. If a strategy is not defined, the method defined in
// Section 6.2 - OEM Installation of IAK and IDevID in a Single Pass of the TCG TPM 2.0
// Keys for Device Identity and Attestation specification is used as the default strategy.
func (tpm *TPM2) VerifyTCGCSR(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	enrollmentStrategy := ParseIdentityProvisioningStrategy(tpm.config.IdentityProvisioningStrategy)
	switch enrollmentStrategy {
	case EnrollmentStrategyIAK:
		return tpm.VerifyTCG_CSR_IAK(csr, signatureAlgorithm)
	case EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
		return tpm.VerifyTCG_CSR_IDevID(csr, signatureAlgorithm)
	}
	return nil, nil, ErrInvalidEnrollmentStrategy
}

// Extracts the Attestation Public Key from TCG_CSR_IDEVID and performs
// verification per TCG TPM 2.0 Keys for Device Identity and Attestation
// per Section 6.1.2 - Procedure for OEM Creation of an IAK Certificate.
// 5. The CA verifies the received data:
// a. Verify the signature on the TCG-CSR-IDEVID:
// i. Extract the IAK Public Key from the IAK Public Area in the TCG-CSR-IDEVID.
// ii. Use the IAK public key to verify the signature on the TCG-CSR-IDEVID.
// b. Extract the EK certificate from the TCG-CSR-IDEVID and verify the EK
// Certificate using the indicated TPM manufacturer's public key.
// c. Verify the attributes (TPMA_OBJECT bits) of the IAK Public Area to ensure
// that the key is a Restricted, fixedTPM, fixedParent signing key. Ensure all
// other attributes meet CA policy.
// Step b is implemented in the pkg/ca package, not here: TPM2 is the device
// side of this exchange (it also drives the EK's own certificate issuance in
// tpm2/ek.go), while the EK certificate's chain of trust is a CA policy
// decision -- which TPM-manufacturer roots to accept -- configured per CA
// (ca.TCGConfig). The CA verifies it, and the tcg-kp-EKCertificate extended
// key usage, before signing an IAK from a CSR this method has verified;
// see (*ca.CA).SignTCGCSRIDevID and the unexported
// (*ca.CA).verifyEKCertificateChain it calls.
func (tpm *TPM2) VerifyTCG_CSR_IAK(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, err
	}

	// Unpack CSR to UNPACKED_TCG_CSR_IDEVID
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// Set the TCG and crypto hash algorithm
	if unpacked.CsrContents.HashAlgoId > math.MaxUint16 {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)}
	}
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId) // #nosec G115 -- TPM algorithm ID from CSR
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Load the AK public area
	loadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.AttestPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Flush(loadRsp.ObjectHandle)

	// Load default TPM attributes for the AK
	keyAttrs, err := tpm.KeyAttributes(loadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}
	keyAttrs.Parent = ekAttrs
	keyAttrs.SignatureAlgorithm = signatureAlgorithm
	keyAttrs.StoreType = types.StoreTPM2
	keyAttrs.TPMAttributes.HashAlg = hashAlgo

	// Set the key algorithm
	if store.IsECDSA(signatureAlgorithm) {
		keyAttrs.KeyAlgorithm = x509.ECDSA
	} else {
		keyAttrs.KeyAlgorithm = x509.RSA
	}

	pub := keyAttrs.TPMAttributes.Public

	// Ensure the AK is a Restricted, fixedTPM, fixedParent signing key
	if !pub.ObjectAttributes.Restricted {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.FixedTPM {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.FixedParent {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !pub.ObjectAttributes.SignEncrypt {
		return nil, nil, store.ErrInvalidKeyAttributes
	}

	// Verify the CSR using the IAK public key
	if err := tpm.verifyTCGCSRSignature(csr, hash, keyAttrs); err != nil {
		return nil, nil, err
	}

	return keyAttrs, unpacked, nil
}

// Extracts the Attestation Public Key from TCG_CSR_IDEVID and performs
// verification per TCG TPM 2.0 Keys for Device Identity and Attestation
// per Section 6.2.2 - Procedure for OEM Installation of IAK and IDevID
// in a Single Pass.
// 7. The CA verifies the received data:
// a. Extract IDevID public key and verify the signature on TCG-CSR-IDEVID
// b. Verify the EK Certificate using the indicated TPM manufacturer's public key
// c. Verify TPM residency of IDevID key using the IAK public key to validate the signature of the
// TPMB_Attest structure.
// d. Verify the attributes of the IDevID key public area.
// e. Verify the attributes of the IAK public area.
// f. Calculate the Name of the IAK, by hashing its public area with its associated hash algorithm,
// prepended with the Algorithm ID of the hashing algorithm. Refer to TPM 2.0 Library Specification [2]
// Part 1, Section 16, "Names".
// g. Using the sequence described in the TPM 2.0 Library Specification [2] Part 3, section 12.6.3
// (TPM2_MakeCredential Detailed Actions), create the encrypted "credential" structure to be sent to
// the device. When building this encrypted structure, objectName is the Name of the IAK calculated in
// step 'a' and Certificate (which is the payload field) holds a nonce (whose size matches the Name
// hash). Retain the nonce for use in later steps.
// Step b is implemented in the pkg/ca package, not here -- see the note on
// VerifyTCG_CSR_IAK above; (*ca.CA).SignTCGCSRIDevID is the entry point for
// this enrollment path and calls the same EK chain verification.
func (tpm *TPM2) VerifyTCG_CSR_IDevID(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error) {

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, err
	}

	// Unpack CSR to UNPACKED_TCG_CSR_IDEVID
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// // Set the TCG and crypto hash algorithm
	if unpacked.CsrContents.HashAlgoId > math.MaxUint16 {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)}
	}
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId) // #nosec G115 -- TPM algorithm ID from CSR
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Load the IAK public area
	iakLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.AttestPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	// TPM2_LoadExternal occupies a transient object slot until it is flushed
	// (TCG TPM 2.0 Library Part 3, section 12.3). Deferring the flush rather
	// than issuing it after KeyAttributes means a malformed public area -- which
	// is attacker-supplied here, since it arrives inside a TCG-CSR-IDEVID -- can
	// no longer strand a slot per rejected CSR.
	defer tpm.Flush(iakLoadRsp.ObjectHandle)

	// Load default TPM attributes for the IAK
	iakAttrs, err := tpm.KeyAttributes(iakLoadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}

	iakPub := iakAttrs.TPMAttributes.Public

	// Ensure the AK is a Restricted, fixedTPM, fixedParent signing key
	if !iakPub.ObjectAttributes.Restricted {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.FixedTPM {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.FixedParent {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !iakPub.ObjectAttributes.SignEncrypt {
		return nil, nil, store.ErrInvalidKeyAttributes
	}

	// Load the IDevID public area
	idevidLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](
			unpacked.CsrContents.SigningPub),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	// Same slot-per-rejected-CSR reasoning as the IAK public area above.
	defer tpm.Flush(idevidLoadRsp.ObjectHandle)

	// Load default TPM attributes for the IDevID
	idevidAttrs, err := tpm.KeyAttributes(idevidLoadRsp.ObjectHandle)
	if err != nil {
		return nil, nil, err
	}

	idevidAttrs.Parent = ekAttrs
	idevidAttrs.SignatureAlgorithm = signatureAlgorithm
	idevidAttrs.StoreType = types.StoreTPM2
	idevidAttrs.TPMAttributes.HashAlg = hashAlgo

	idevidPub := idevidAttrs.TPMAttributes.Public

	// Ensure the IDevID is an Unrestricted, fixedTPM, fixedParent signing key
	if idevidPub.ObjectAttributes.Restricted {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.FixedTPM {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.FixedParent {
		return nil, nil, store.ErrInvalidKeyAttributes
	}
	if !idevidPub.ObjectAttributes.SignEncrypt {
		return nil, nil, store.ErrInvalidKeyAttributes
	}

	// Set the signing key algorithm
	if store.IsECDSA(signatureAlgorithm) {
		idevidAttrs.KeyAlgorithm = x509.ECDSA
	} else {
		idevidAttrs.KeyAlgorithm = x509.RSA
	}

	// Verify the CSR using the IDevID public key
	if err := tpm.verifyTCGCSRSignature(csr, hash, idevidAttrs); err != nil {
		return nil, nil, err
	}

	return idevidAttrs, unpacked, nil
}

// Verifies the TCG-CSR-IDEVID signature using the provided hash and key attributes
func (tpm *TPM2) verifyTCGCSRSignature(
	csr *TCG_CSR_IDEVID,
	hash crypto.Hash,
	keyAttrs *types.KeyAttributes) error {

	pub := keyAttrs.TPMAttributes.Public

	// Re-pack the CSR contents to get the digest
	packedContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return err
	}

	// Perform hash sequence on the (large) digest
	digest, _, err := tpm.HashSequence(keyAttrs, packedContents)
	if err != nil {
		return err
	}

	// Verify the TCG-CSR-IDEVID signature
	if pub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

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

		if store.IsRSAPSS(keyAttrs.SignatureAlgorithm) {

			// RSA PSS
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}
			err = rsa.VerifyPSS(
				rsaPub, hash, digest, csr.Signature, pssOpts)
			if err != nil {
				return ErrInvalidSignature
			}

		} else {

			err = rsa.VerifyPKCS1v15(rsaPub, hash, digest, csr.Signature)
			if err != nil {
				return ErrInvalidSignature
			}

		}

	} else if pub.Type == tpm2.TPMAlgECC {

		ecdsaPub, err := eccPublicKey(&pub)
		if err != nil {
			return err
		}

		if !ecdsa.VerifyASN1(ecdsaPub, digest, csr.Signature) {
			return ErrInvalidSignature
		}
	}

	return nil
}
