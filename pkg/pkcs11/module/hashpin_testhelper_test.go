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

package module

// mustHashPin wraps hashPin for tests that used it as a value before it returned
// an error (C24). crypto/rand never fails in a test, so panicking on the error
// is fine and keeps the call sites terse.
func mustHashPin(pin string) []byte {
	h, err := hashPin(pin)
	if err != nil {
		panic(err)
	}
	return h
}

// mustGenerateSerialNumber is the generateSerialNumber analog for tests.
func mustGenerateSerialNumber() string {
	s, err := generateSerialNumber()
	if err != nil {
		panic(err)
	}
	return s
}
