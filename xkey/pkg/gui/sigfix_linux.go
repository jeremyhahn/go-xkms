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

//go:build linux

package gui

/*
#include <signal.h>

// fixSignalHandlers ensures that any C-installed signal handlers
// (particularly from WebKit/JSC) have the SA_ONSTACK flag set.
// Go 1.24+ fatally crashes when it detects a signal handler without
// SA_ONSTACK because the handler would run on the goroutine stack
// instead of the signal-alternate stack. WebKit's JSC JIT engine
// installs handlers for SIGSEGV and SIGBUS without this flag.
static void fixSignalHandlers() {
	int signals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGABRT};
	int i;
	for (i = 0; i < 4; i++) {
		struct sigaction sa;
		if (sigaction(signals[i], NULL, &sa) == 0) {
			if (sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
				if (!(sa.sa_flags & SA_ONSTACK)) {
					sa.sa_flags |= SA_ONSTACK;
					sigaction(signals[i], &sa, NULL);
				}
			}
		}
	}
}
*/
import "C"

// FixSignalHandlers patches C-installed signal handlers to include
// SA_ONSTACK, preventing Go 1.24+ from fatally crashing. Must be
// called after Wails/WebKit has initialized (in the startup hook).
func FixSignalHandlers() {
	C.fixSignalHandlers()
}
