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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/secureio"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSecureBuffer(t *testing.T, plain string) *secure.Buffer {
	t.Helper()
	buf, err := secure.NewBufferFromBytes([]byte(plain))
	require.NoError(t, err)
	return buf
}

// TestBuffersProvider_ClonesIndependently proves the provider returns a clone
// whose destruction leaves the handler's own buffer readable.
func TestBuffersProvider_ClonesIndependently(t *testing.T) {
	orig := newTestSecureBuffer(t, "hunter2")
	defer orig.Destroy()
	provider := &buffersProvider{buf: orig}

	clone, err := provider.Passphrase(context.Background(), "k")
	require.NoError(t, err)
	require.NoError(t, clone.WithBytes(func(b []byte) error {
		assert.Equal(t, []byte("hunter2"), b)
		return nil
	}))
	clone.Destroy()

	require.NoError(t, orig.WithBytes(func(b []byte) error {
		assert.Equal(t, []byte("hunter2"), b)
		return nil
	}))
}

// TestBuffersProvider_RefusesAbsentOrDestroyed proves a nil provider, a nil
// buffer and a destroyed buffer all yield *SSHNilError and no buffer.
func TestBuffersProvider_RefusesAbsentOrDestroyed(t *testing.T) {
	destroyed := newTestSecureBuffer(t, "x")
	destroyed.Destroy()

	for name, p := range map[string]*buffersProvider{
		"nil provider": nil,
		"nil buffer":   {},
		"destroyed":    {buf: destroyed},
	} {
		t.Run(name, func(t *testing.T) {
			buf, err := p.Passphrase(context.Background(), "k")
			var nilErr *SSHNilError
			require.True(t, errors.As(err, &nilErr), "got %v", err)
			assert.Nil(t, buf)
		})
	}
}

// TestBarrierCredentialsFromRequest_CopiesWithoutConsuming proves the
// credentials are built from a copy: the request's own field survives and can
// still be destroyed by the handler.
func TestBarrierCredentialsFromRequest_CopiesWithoutConsuming(t *testing.T) {
	var req struct {
		Password secureio.PasswordField `json:"password_b64"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"password_b64":"aHVudGVyMg=="}`), &req))
	defer req.Password.Destroy()

	creds, ok, err := barrierCredentialsFromRequest(req.Password)
	require.NoError(t, err)
	require.True(t, ok)
	defer creds.Secret.Destroy()
	assert.NotNil(t, creds.Secret)

	require.NoError(t, req.Password.Buffer().WithBytes(func(b []byte) error {
		assert.Equal(t, []byte("hunter2"), b)
		return nil
	}))
}

// TestBarrierCredentialsFromRequest_Absent proves an absent password reports
// ok=false with the zero Credentials rather than an error.
func TestBarrierCredentialsFromRequest_Absent(t *testing.T) {
	creds, ok, err := barrierCredentialsFromRequest(secureio.PasswordField{})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, creds.Secret)
}
