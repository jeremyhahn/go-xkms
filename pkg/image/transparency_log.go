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

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TransparencyLog records image signatures; the CA's transparency log
// (*tlog.Log) satisfies it.
type TransparencyLog interface {
	// AppendImageSigned appends an image-signed entry and returns its index.
	AppendImageSigned(ctx context.Context, e tlog.ImageSigned) (uint64, error)
}

// appendImageSigned records the signature envelope over digest in the
// Signer's transparency log. It is a no-op without one. A failed append
// returns ErrTransparencyLogAppend: the caller pushes and returns nothing
// the log does not hold.
func (s *Signer) appendImageSigned(ctx context.Context, digest string, envelope []byte) error {
	if s.transparencyLog == nil {
		return nil
	}
	sum := sha256.Sum256(envelope)
	entry := tlog.ImageSigned{
		ImageDigest:    digest,
		EnvelopeDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Signer:         s.certificate.Subject.String(),
	}
	if _, err := s.transparencyLog.AppendImageSigned(ctx, entry); err != nil {
		return &errs.Joined{Lead: ErrTransparencyLogAppend, Detail: digest, Cause: err}
	}
	return nil
}
