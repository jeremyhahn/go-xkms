// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cli

import (
	"fmt"
	"testing"
)

// ExitError represents an exit call captured during testing.
type ExitError struct {
	Code int
}

func (e ExitError) Error() string {
	return fmt.Sprintf("exit(%d)", e.Code)
}

// withTestExit temporarily replaces exitFunc with a function that panics
// with an ExitError, allowing tests to verify error handling paths.
// It restores the original exitFunc after the test function completes.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//	    withTestExit(t, func() {
//	        // Code that calls handleError
//	        someFunctionThatMayCallHandleError()
//	    }, func(code int) {
//	        // Verify the exit code
//	        if code != 1 {
//	            t.Errorf("expected exit code 1, got %d", code)
//	        }
//	    })
//	}
func withTestExit(t *testing.T, fn func(), onExit func(code int)) {
	t.Helper()

	oldExit := exitFunc
	defer func() { exitFunc = oldExit }()

	var exitCalled bool
	var exitCode int

	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
		panic(ExitError{Code: code})
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(ExitError); !ok {
					panic(r) // Re-panic if not an ExitError
				}
			}
		}()
		fn()
	}()

	if exitCalled && onExit != nil {
		onExit(exitCode)
	}
}

// captureExit temporarily replaces exitFunc to capture exit calls without panicking.
// Returns the exit code if exit was called, or -1 if exit was not called.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//	    code := captureExit(t, func() {
//	        someFunctionThatMayCallHandleError()
//	    })
//	    if code != 1 {
//	        t.Errorf("expected exit code 1, got %d", code)
//	    }
//	}
func captureExit(t *testing.T, fn func()) int {
	t.Helper()

	oldExit := exitFunc
	defer func() { exitFunc = oldExit }()

	exitCode := -1
	exitFunc = func(code int) {
		exitCode = code
		// Don't actually exit - just record the code
	}

	fn()
	return exitCode
}

// TestHandleError_ExitsWithCode1 verifies handleError calls exit with code 1.
func TestHandleError_ExitsWithCode1(t *testing.T) {
	// Save original config
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	code := captureExit(t, func() {
		handleError(fmt.Errorf("test error"))
	})

	if code != 1 {
		t.Errorf("handleError() should exit with code 1, got %d", code)
	}
}

// TestHandleError_WithPanic verifies handleError behavior using panic capture.
func TestHandleError_WithPanic(t *testing.T) {
	// Save original config
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	globalConfig.OutputFormat = "text"

	withTestExit(t, func() {
		handleError(fmt.Errorf("test error"))
	}, func(code int) {
		if code != 1 {
			t.Errorf("handleError() should exit with code 1, got %d", code)
		}
	})
}
