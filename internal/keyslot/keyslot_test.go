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

package keyslot

import "testing"

type fixed struct{}
type perName struct{}

func TestFixed_AsksTheRegisteredProbes(t *testing.T) {
	if Fixed(fixed{}) {
		t.Fatal("a provider no probe knows must not report a fixed slot")
	}
	unregister := Register(func(p any) (bool, bool) {
		switch p.(type) {
		case fixed:
			return true, true
		case perName:
			return false, true
		}
		return false, false
	})
	if !Fixed(fixed{}) {
		t.Fatal("the probe reports a fixed slot")
	}
	if Fixed(perName{}) {
		t.Fatal("the probe reports a key per name")
	}
	unregister()
	if Fixed(fixed{}) {
		t.Fatal("an unregistered probe is still asked")
	}
}
