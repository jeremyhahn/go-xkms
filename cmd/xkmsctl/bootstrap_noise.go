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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// noiseCmd represents the noise command group
var noiseCmd = &cobra.Command{
	Use:   "noise",
	Short: "Noise protocol key management",
	Long:  `Manage Noise protocol static keys and compute SPKI pins for secure bootstrap.`,
}

// noiseGenerateKeyCmd generates a new Noise static keypair
var noiseGenerateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a new Noise static keypair",
	Long: `Generate a new Curve25519 static keypair for the Noise protocol.

The private key is written, hex-encoded, to the file named by --output, which
is created with 0600 permissions and must not already exist. It is never
printed: stdout is read by terminal scrollback, shell history, pipes and CI
logs, none of which can be wiped. The public key is displayed for distribution
to clients.`,
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		outputFile := fr.String("output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		generateNoiseKey(outputFile)
	},
}

// noiseShowKeyCmd shows the public key from a private key
var noiseShowKeyCmd = &cobra.Command{
	Use:   "show-key",
	Short: "Show public key from a Noise static key",
	Long:  `Derive and display the public key from a Noise static private key file or hex string.`,
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		keyFile := fr.String("key-file")
		keyHex := fr.String("key-hex")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		showNoiseKey(keyFile, keyHex)
	},
}

// noiseShowSPKIPinCmd computes the SPKI SHA-256 pin from a TLS certificate
var noiseShowSPKIPinCmd = &cobra.Command{
	Use:   "show-spki-pin",
	Short: "Compute SPKI SHA-256 pin from a TLS certificate file",
	Long: `Compute and display the SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
from a server's TLS certificate. This pin is used for SPKI-pinned TLS bootstrap.

The pin is computed from a PEM certificate file (--cert-file). To obtain the
server's certificate, use: openssl s_client -connect host:port </dev/null | openssl x509 > cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		certFile := fr.String("cert-file")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		showSPKIPin(certFile)
	},
}

// generateNoiseKey generates a Noise static keypair and writes the private
// half to outputFile. The private key is never printed: a hex-encoded static
// key on stdout survives in scrollback, shell history and CI logs, none of
// which can be wiped, so the file is the only sink.
func generateNoiseKey(outputFile string) {
	if outputFile == "" {
		handleError(ErrOutputFileRequired)
		return
	}

	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGenerateKeyFailed, Err: err})
		return
	}
	defer key.Destroy()

	// The hex encoding is as sensitive as the scalar it encodes, so it gets
	// the same treatment: a guard-paged, swap-locked buffer outside the Go
	// heap, destroyed on the way out. EncodeStaticKey's contract asks for a
	// protected destination, and an ordinary make([]byte) cannot honour it —
	// wiping afterwards does nothing about the copies the GC may already have
	// made, or about the page reaching swap in between. Unlike the P-256 path,
	// EncodeNoiseStaticKey takes a plain []byte destination, so the SDK's
	// secure.Buffer (never a raw memguard.LockedBuffer) is sufficient here.
	buf, err := secure.NewBuffer(bootstrap.NoiseHexKeySize + 1)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGenerateKeyFailed, Err: err})
		return
	}
	defer buf.Destroy()

	// The borrow is held across the encode and the file write, so a
	// concurrent shutdown wipe cannot unmap the pages mid-read.
	if err := buf.WithBytes(func(encoded []byte) error {
		if err := bootstrap.EncodeNoiseStaticKey(encoded, key); err != nil {
			return &WrappedError{Sentinel: ErrEncodeKeyFailed, Err: err}
		}
		encoded[bootstrap.NoiseHexKeySize] = '\n'
		if err := writeNoiseKeyFile(outputFile, encoded); err != nil {
			return &WrappedError{Sentinel: ErrWriteKeyFileFailed, Err: err}
		}
		return nil
	}); err != nil {
		handleError(err)
		return
	}

	publicHex := hex.EncodeToString(key.Public)

	fmt.Printf("Private key written to: %s\n", outputFile)
	fmt.Printf("Public key:  %s\n", publicHex)
}

// noiseKeyFile is what writeNoiseKeyFile needs of the handle it writes
// through: write it, close it, and identify it on disk. Stat is what makes
// the failure cleanup safe, so it is part of the contract rather than a type
// assertion at the point of use. *os.File satisfies it.
type noiseKeyFile interface {
	io.WriteCloser
	Stat() (os.FileInfo, error)
}

// createNoiseKeyFile creates the private-key file, failing if it already
// exists. It is a variable so tests can substitute a handle that fails
// mid-write and assert the partial file is cleaned up.
var createNoiseKeyFile = func(path string) (noiseKeyFile, error) {
	// O_EXCL, not os.WriteFile: WriteFile applies its mode only when it
	// creates the file, so writing over an existing 0644 path would leave the
	// private key world-readable. Refusing an existing path also stops a
	// second run from silently replacing a Noise identity that peers have
	// already pinned.
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

// writeNoiseKeyFile writes the hex-encoded private key to path, creating it at
// mode 0600 and refusing to overwrite.
//
// A write or close that fails removes the file it created. Leaving it behind
// would strand a truncated private key on disk and, because the next attempt
// refuses an existing path, would block the retry that replaces it.
func writeNoiseKeyFile(path string, encoded []byte) error {
	f, err := createNoiseKeyFile(path)
	if err != nil {
		return err
	}

	// The byte count matters, not just the error. A compliant io.Writer must
	// error on a short write, but this one is injectable for tests and the
	// cost of being wrong is a truncated private key reported as persisted.
	n, err := f.Write(encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}

	// Identify the file while the descriptor is still open. Stat on a closed
	// handle fails, and this identity is the whole basis of removeIfSame. A
	// stat that fails leaves created nil, which means "do not remove".
	created, statErr := f.Stat()
	if statErr != nil {
		created = nil
	}

	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		removeIfSame(created, path)
		return err
	}
	return nil
}

// removeIfSame unlinks path only while it still names the file described by
// created.
//
// An unconditional os.Remove unlinks whatever holds the name NOW, not the
// file the failure produced. Anything with write access to the parent
// directory can rename our partial key away and drop an unrelated file at the
// same path in between, and the cleanup would then delete that file instead —
// destroying somebody else's data in the name of tidying up after ourselves.
//
// The trade when identity cannot be established: leave the file. A stranded
// partial key file is reported to the caller and refused by the next run's
// O_EXCL; a wrong unlink is silent and irreversible.
//
// KNOWN AND IRREDUCIBLE: the check and the unlink are not atomic, so a
// substitution landing between them is still removed. This is narrowed, not
// eliminated — the window went from the whole write-and-close to the gap
// between an fstat and an unlink — and it cannot be closed with what the
// platform offers. Linux has no unlink-by-inode; unlinkat resolves a name
// like unlink does, so a directory file descriptor buys nothing here. The
// alternative that WOULD close it is not removing the file at all, which
// strands a partial private key that the next run's O_EXCL then refuses,
// turning a rare race into a guaranteed failed retry. Reviewed and kept
// deliberately.
func removeIfSame(created os.FileInfo, path string) {
	if created == nil {
		return
	}

	// Lstat, so a symlink swapped in for our file is compared as the symlink
	// it is and fails the identity check rather than being followed.
	onDisk, err := os.Lstat(path)
	if err != nil || !os.SameFile(created, onDisk) {
		return
	}

	if err := os.Remove(path); err != nil {
		slog.Default().Debug("xkmsctl: cleanup remove failed", "path", path, "error", err)
	}
}

func showNoiseKey(keyFile, keyHex string) {
	var hexKey []byte

	switch {
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadKeyFileFailed, Err: err})
			return
		}
		// The file bytes are ours to wipe once decoded; TrimSpace returns a
		// subslice of the same backing array, so wiping data covers both.
		defer bootstrap.WipeNoiseBytes(data)
		hexKey = bytes.TrimSpace(data)
	case keyHex != "":
		// --key-hex came in on the command line and is already visible in the
		// process table and shell history, so there is nothing left to
		// protect in this copy.
		hexKey = []byte(keyHex)
	default:
		handleError(ErrKeyInputRequired)
		return
	}

	key, err := bootstrap.DecodeNoiseStaticKey(hexKey)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDecodeKeyFailed, Err: err})
		return
	}
	defer key.Destroy()

	fmt.Printf("Public key: %s\n", hex.EncodeToString(key.Public))
}

func showSPKIPin(certFile string) {
	if certFile == "" {
		handleError(ErrCertFileRequired)
		return
	}

	// Read PEM certificate file
	data, err := os.ReadFile(certFile)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCertFileRead, Err: err})
		return
	}

	// Parse PEM
	block, _ := pem.Decode(data)
	if block == nil {
		handleError(ErrNoPEMData)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrParseCertificateFailed, Err: err})
		return
	}

	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Printf("SPKI SHA-256 pin: %s\n", hex.EncodeToString(pin[:]))
	fmt.Printf("Subject:          %s\n", cert.Subject.String())
	fmt.Printf("Issuer:           %s\n", cert.Issuer.String())
	fmt.Printf("Not Before:       %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:        %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
}
