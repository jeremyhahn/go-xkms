package tpm2

import (
	"fmt"
	"io"
	"math"

	"github.com/google/go-tpm/tpm2"
)

// Maximum bytes that can be requested from TPM2_GetRandom in a single call.
// Most TPM implementations return between 48-64 bytes per call.
// Using 48 as a conservative value to ensure compatibility.
const maxRandomBytesPerRequest = 48

// Returns the TPM Random Number Generator source. If "entropy" is
// enabled in the platform configuration file, the TPM will be used
// as the source of entropy. If "entropy" is disabled, the system
// random number generator will be used as the source of entropy.
func (tpm *TPM2) RandomSource() io.Reader {
	return tpm.random
}

// Reads random bytes from the TPM into the data buffer. Optionally
// uses the EK to encrypt the session between the CPU <-> TPM if
// session encryption is enabled in the platform configuration file.
// If the TPM Endorsement Hierarchy authorization has an authorization
// password set, and the EK has not been made persistent, the
// tpm.hierarchyAuth property must be set before reading so a transient
// EK can be created (under the Endorsement Hierarchy) to encrypt the
// session. The hierarchy auth is automatically set during provisioning
// - ie, when Provision() is called. After provisioning is complete,
// subsequent platform startups will have to explicitly provide the hierarchy
// password, since it's never saved, loaded, or cached during normal operation.
// The hierarchy password is only cached in memory during provisioning and
// wiped from memory when the program exits.
//
// This function handles the TPM2_GetRandom limitation where the TPM may
// return fewer bytes than requested (typically 48-64 bytes max per call).
// It loops to collect random bytes in chunks until the requested size is fulfilled.
func (tpm *TPM2) Read(data []byte) (n int, err error) {

	totalRequested := len(data)
	totalRead := 0

	for totalRead < totalRequested {
		remaining := totalRequested - totalRead
		chunkSize := remaining
		if chunkSize > maxRandomBytesPerRequest {
			chunkSize = maxRandomBytesPerRequest
		}

		bytesRead, err := tpm.readChunk(data[totalRead:totalRead+chunkSize], chunkSize)
		if err != nil {
			return totalRead, err
		}

		if bytesRead == 0 {
			return totalRead, ErrUnexpectedRandomBytes
		}

		totalRead += bytesRead
	}

	return totalRead, nil
}

// readChunk reads a single chunk of random bytes from the TPM.
// This is an internal helper function that handles the actual TPM call.
func (tpm *TPM2) readChunk(data []byte, requestSize int) (int, error) {

	var sess tpm2.Session

	if tpm.config.EncryptSession {

		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		response, err := tpm2.ReadPublic{
			ObjectHandle: ekHandle,
		}.Execute(tpm.transport)
		if err != nil {

			tpm.logger.MaybeError(err)

			ekAttrs, err := tpm.EKAttributes()
			if err != nil {
				return 0, err
			}
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(
					128,
					tpm2.EncryptOut),
				tpm2.Salted(ekAttrs.TPMAttributes.Handle, ekAttrs.TPMAttributes.Public))

		} else {

			// Use the persistent EK handle to encrypt the session
			ekPub, err := response.OutPublic.Contents()
			if err != nil {
				tpm.logger.Error(err)
				return 0, err
			}
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(
					128,
					tpm2.EncryptOut),
				tpm2.Salted(ekHandle, *ekPub))
		}

	} else {
		// No key available to salt the connection
		sess = tpm2.HMAC(
			tpm2.TPMAlgSHA256,
			16,
			tpm2.AESEncryption(128, tpm2.EncryptOut))
	}

	// Get the random bytes
	if requestSize > math.MaxUint16 {
		return 0, fmt.Errorf("request size too large: %d", requestSize)
	}
	resp, err := tpm2.GetRandom{
		BytesRequested: uint16(requestSize), // #nosec G115 -- Bounds checked above
	}.Execute(tpm.Transport(), sess)
	if err != nil {
		tpm.logger.Error(err)
		return 0, err
	}

	bytesReceived := len(resp.RandomBytes.Buffer)
	if bytesReceived > len(data) {
		bytesReceived = len(data)
	}
	copy(data, resp.RandomBytes.Buffer[:bytesReceived])

	return bytesReceived, nil
}

// Reads a random 32 byte fixed length slice from RNG
func (tpm *TPM2) Random() ([]byte, error) {

	var err error
	var n int
	fixedLength := 32
	bytes := make([]byte, fixedLength)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	if n != fixedLength {
		return nil, ErrUnexpectedRandomBytes
	}

	tpm.logger.Debugf("tpm: read %d random bytes", n)

	return bytes, nil
}

// Reads a random fixed length byte slice from RNG
func (tpm *TPM2) RandomBytes(fixedLength int) ([]byte, error) {

	if fixedLength <= 0 {
		return nil, ErrInvalidRandomBytesLength
	}

	var err error
	var n int
	bytes := make([]byte, fixedLength)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	if n != fixedLength {
		return nil, ErrUnexpectedRandomBytes
	}

	tpm.logger.Debugf("tpm: read %d random bytes", n)

	return bytes, nil
}

// Reads a random fixed length byte slice from RNG and
// returns the resulting bytes encoded in hexidecimal format.
func (tpm *TPM2) RandomHex(fixedLength int) ([]byte, error) {

	if fixedLength <= 0 || fixedLength%2 != 0 {
		return nil, ErrInvalidRandomBytesLength
	}

	var err error
	var n int
	len := fixedLength / 2
	bytes := make([]byte, len)

	// Read fixed length bytes
	n, err = tpm.Read(bytes)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, ErrUnexpectedRandomBytes
	}

	tpm.logger.Debugf("tpm: read %d random bytes", n)

	return []byte(Encode(bytes)), nil
}
