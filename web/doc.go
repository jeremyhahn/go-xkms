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

// Package web hosts the compiled single-page web UI embedded into xkmsd.
//
// The vite dist output is embedded only when the binary is built with the
// "ui" build tag: embed.go carries the //go:embed directive behind that tag,
// so building it requires web/dist to exist (produced by the web build).
// Every other build compiles embed_stub.go instead, whose Assets returns
// (nil, false), keeping `go build ./...` green without a dist directory.
// cmd/xkmsd calls Assets and installs the returned filesystem on the server
// via SetUIAssets when ok is true.
package web
