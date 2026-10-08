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
	"errors"
	"testing"

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
