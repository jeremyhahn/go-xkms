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
	"testing"

	"github.com/stretchr/testify/assert"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// The canonical login key must survive the proto -> transport projection.
//
// Email was added to the server-side projection (userInfoToProto) and to the
// CreateUser request, but not here — so a gRPC client sent the key, the server
// stored and returned it, and the client read it back empty. The key this PR
// makes required was unreadable over the transports that carry it as a typed
// field, while REST and QUIC preserved it through generic JSON (Codex,
// go-xkms #190).
func TestProtoToUserInfo_CarriesEmail(t *testing.T) {
	got := protoToUserInfo(&pb.UserInfo{
		Id:          7,
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		Roles:       []string{"admin", "auditor"},
		Enabled:     true,
	})

	assert.Equal(t, "alice@example.com", got.Email, "the canonical login key was dropped in projection")
	assert.Equal(t, "alice", got.Username)
	assert.Equal(t, "Alice Smith", got.DisplayName)
	assert.Equal(t, []string{"admin", "auditor"}, got.Roles)
	assert.True(t, got.Enabled)
}

func TestProtoToUserInfo_NilIsZero(t *testing.T) {
	assert.Equal(t, "", protoToUserInfo(nil).Email)
}
