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

//go:build !unix

package cmd

import (
	"errors"
	"os"
)

// errSRKEnrollmentLockUnsupported is returned where no advisory file lock
// exists to serialize Platform SRK enrolment across processes.
var errSRKEnrollmentLockUnsupported = errors.New("tpm srk: the Platform SRK enrolment lock is supported only on unix")

// lockFileExclusive refuses on platforms without flock, so enrolment never
// runs unserialized.
func lockFileExclusive(_ *os.File) error {
	return errSRKEnrollmentLockUnsupported
}

// unlockFile is the counterpart of lockFileExclusive; nothing is held.
func unlockFile(_ *os.File) error {
	return nil
}
