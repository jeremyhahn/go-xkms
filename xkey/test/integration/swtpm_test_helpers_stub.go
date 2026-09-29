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

//go:build integration && linux && !tpm_simulator

// Package xkey — stub swtpm lifecycle for integration test binaries built
// without the tpm_simulator tag. TPM2 barrier CLI tests (barrier_tpm2_test.go,
// tpm_policy_test.go) are themselves gated on tpm_simulator and are absent
// from this build, so there is nothing to stop; this stub exists solely so
// main_test.go's TestMain can call stopSwtpmForTests unconditionally
// regardless of which tag set the binary was built with.
package xkey

// stopSwtpmForTests is a no-op: no swtpm process was ever started in a
// build without the tpm_simulator tag.
func stopSwtpmForTests() {}
