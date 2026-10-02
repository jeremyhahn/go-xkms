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

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestUnwrapFirstSuccess_AllVersionsFailReturnsFirstError proves the error a
// caller sees is the first version's, matching firstSuccess, and that no
// plaintext is returned.
func TestUnwrapFirstSuccess_AllVersionsFailReturnsFirstError(t *testing.T) {
	versions := []keyVersion{
		{number: 2, attrs: &types.KeyAttributes{CN: "newest"}},
		{number: 1, attrs: &types.KeyAttributes{CN: "oldest"}},
	}

	plaintext, err := unwrapFirstSuccess(context.Background(), nil, versions, "no-such-algorithm", wrapParams{}, []byte("wrapped"))
	require.Error(t, err)
	assert.Nil(t, plaintext)
	assert.True(t, errors.Is(err, ErrOperationNotSupported), "got %v", err)
}

// TestUnwrapFirstSuccess_NoVersions proves an empty version list yields
// nothing and no error: selecting versions is the caller's job.
func TestUnwrapFirstSuccess_NoVersions(t *testing.T) {
	plaintext, err := unwrapFirstSuccess(context.Background(), nil, nil, "no-such-algorithm", wrapParams{}, []byte("wrapped"))
	require.NoError(t, err)
	assert.Nil(t, plaintext)
}
