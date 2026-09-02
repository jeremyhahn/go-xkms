// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// A missing canonical login key is client input, not a server fault.
//
// Every CreateUser failure was mapped to Internal, so a caller that simply
// omitted the email was told the server had broken — and told to retry a
// request that can never succeed (Codex, go-xkms #190).
func TestCreateUserErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"missing login key is client input", xkms.ErrEmailRequired, codes.InvalidArgument},
		{"wrapped by the service is still client input",
			&xkms.ErrUserOperation{Operation: "create user", Err: xkms.ErrEmailRequired},
			codes.InvalidArgument},
		{"anything else remains internal", errors.New("store unavailable"), codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := createUserErrorCode(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
