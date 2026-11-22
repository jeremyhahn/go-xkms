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

package localtpm

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
)

// ReferenceSignerFile is the file in a local data directory that names the
// trusted reference-value signer: PEM "PUBLIC KEY" blocks pin the signer,
// PEM "CERTIFICATE" blocks are the roots a signer's x5chain must reach.
const ReferenceSignerFile = "tpm-reference-signer.pem"

// ErrReferenceSignerInvalid is returned when the reference signer file
// holds no usable public key or certificate.
var ErrReferenceSignerInvalid = errors.New("localtpm: invalid reference signer file")

// LoadReferenceSigner reads ReferenceSignerFile from dataDir. A missing file
// configures no signer (nil, nil): signed branch updates stay refused with
// tpmpolicy.ErrNoReferenceSigner. A file that is present but names no
// usable key or certificate is refused with ErrReferenceSignerInvalid.
func LoadReferenceSigner(dataDir string) (*refvalue.VerifyOptions, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, ReferenceSignerFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("localtpm: read reference signer: %w", err)
	}
	opts := &refvalue.VerifyOptions{}
	found := false
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PUBLIC KEY":
			if opts.PublicKey != nil {
				return nil, fmt.Errorf("%w: more than one PUBLIC KEY block", ErrReferenceSignerInvalid)
			}
			pub, perr := x509.ParsePKIXPublicKey(block.Bytes)
			if perr != nil {
				return nil, fmt.Errorf("%w: %v", ErrReferenceSignerInvalid, perr)
			}
			opts.PublicKey = pub
		case "CERTIFICATE":
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr != nil {
				return nil, fmt.Errorf("%w: %v", ErrReferenceSignerInvalid, perr)
			}
			if opts.Roots == nil {
				opts.Roots = x509.NewCertPool()
			}
			opts.Roots.AddCert(cert)
		default:
			return nil, fmt.Errorf("%w: unexpected PEM block %q", ErrReferenceSignerInvalid, block.Type)
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("%w: no PUBLIC KEY or CERTIFICATE block", ErrReferenceSignerInvalid)
	}
	return opts, nil
}
