// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// hardenProcess applies process hardening to the application that loaded this
// module, once, on its first C_Initialize.
//
// This module has no main of its own, so C_Initialize stands in for one: it is
// the call PKCS#11 requires before any other, so it runs before a PIN or key
// enters protected memory, and it can refuse with a CK_RV. A library
// constructor would instead run in every process that merely dlopens the
// module — p11-kit enumerating its modules, for one — and could only report
// failure by aborting the host. Once, because an application may initialize
// again after C_Finalize, and the outcome does not change.
//
// Like the module's other helpers it answers with a CK_RV rather than a Go
// error, which the C_Initialize export returns as-is; the error itself is
// logged here because a CK_RV cannot carry it.
var hardenProcess = sync.OnceValue(func() module.CK_RV {
	if _, err := secure.HardenProcess(nil); err != nil {
		slog.Error("pkcs11: process hardening failed; refusing to initialize", "error", err)
		return module.CKR_GENERAL_ERROR
	}
	return module.CKR_OK
})
