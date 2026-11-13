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

package image

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testSHA256 = "sha256:" + strings.Repeat("ab", 32)
	testSHA512 = "sha512:" + strings.Repeat("cd", 64)
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Reference
	}{
		{
			name:     "registry and tag",
			input:    "gcr.io/my-project/my-image:v1.0.0",
			expected: Reference{Registry: "gcr.io", Repository: "my-project/my-image", Tag: "v1.0.0"},
		},
		{
			name:     "registry and digest",
			input:    "gcr.io/my-project/my-image@" + testSHA256,
			expected: Reference{Registry: "gcr.io", Repository: "my-project/my-image", Digest: testSHA256},
		},
		{
			name:     "tag and digest",
			input:    "gcr.io/my-image:v1@" + testSHA256,
			expected: Reference{Registry: "gcr.io", Repository: "my-image", Tag: "v1", Digest: testSHA256},
		},
		{
			name:     "docker hub organization",
			input:    "myorg/myimage:latest",
			expected: Reference{Registry: DefaultRegistry, Repository: "myorg/myimage", Tag: "latest"},
		},
		{
			name:     "docker hub official image",
			input:    "nginx:1.21",
			expected: Reference{Registry: DefaultRegistry, Repository: "library/nginx", Tag: "1.21"},
		},
		{
			name:     "no tag defaults to latest",
			input:    "nginx",
			expected: Reference{Registry: DefaultRegistry, Repository: "library/nginx", Tag: DefaultTag},
		},
		{
			name:     "localhost registry",
			input:    "localhost:5000/myimage:test",
			expected: Reference{Registry: "localhost:5000", Repository: "myimage", Tag: "test"},
		},
		{
			name:     "bare localhost registry",
			input:    "localhost/myimage",
			expected: Reference{Registry: "localhost", Repository: "myimage", Tag: DefaultTag},
		},
		{
			name:     "registry with port",
			input:    "registry.example.com:5000/path/to/image:v2",
			expected: Reference{Registry: "registry.example.com:5000", Repository: "path/to/image", Tag: "v2"},
		},
		{
			name:     "ip registry with port",
			input:    "127.0.0.1:8443/app",
			expected: Reference{Registry: "127.0.0.1:8443", Repository: "app", Tag: DefaultTag},
		},
		{
			name:     "sha512 digest",
			input:    "myregistry.io/myimage@" + testSHA512,
			expected: Reference{Registry: "myregistry.io", Repository: "myimage", Digest: testSHA512},
		},
		{
			name:     "surrounding whitespace",
			input:    "  nginx:1.21  ",
			expected: Reference{Registry: DefaultRegistry, Repository: "library/nginx", Tag: "1.21"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseReference(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *result)
		})
	}
}

func TestParseReference_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		err   error
	}{
		{name: "empty", input: "", err: ErrInvalidReference},
		{name: "whitespace only", input: "   ", err: ErrInvalidReference},
		{name: "digest without algorithm", input: "nginx@invalid", err: ErrInvalidDigest},
		{name: "short digest", input: "nginx@sha256:abc123", err: ErrInvalidDigest},
		{name: "unknown digest algorithm", input: "nginx@md5:" + strings.Repeat("a", 32), err: ErrInvalidDigest},
		{name: "uppercase digest", input: "nginx@sha256:" + strings.Repeat("AB", 32), err: ErrInvalidDigest},
		{name: "invalid tag", input: "nginx:-bad", err: ErrInvalidReference},
		{name: "tag too long", input: "nginx:" + strings.Repeat("a", maxTagLength+1), err: ErrInvalidReference},
		{name: "uppercase repository", input: "gcr.io/MyImage:v1", err: ErrInvalidReference},
		{name: "empty repository", input: "gcr.io/:v1", err: ErrInvalidReference},
		{name: "invalid registry", input: "-bad.io/image:v1", err: ErrInvalidReference},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseReference(tt.input)
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, result)
		})
	}
}

func TestReference_String(t *testing.T) {
	tests := []struct {
		name      string
		reference Reference
		expected  string
	}{
		{
			name:      "tag",
			reference: Reference{Registry: "gcr.io", Repository: "project/image", Tag: "v1"},
			expected:  "gcr.io/project/image:v1",
		},
		{
			name:      "digest",
			reference: Reference{Registry: "gcr.io", Repository: "project/image", Digest: testSHA256},
			expected:  "gcr.io/project/image@" + testSHA256,
		},
		{
			name:      "tag and digest",
			reference: Reference{Registry: "gcr.io", Repository: "image", Tag: "v1", Digest: testSHA256},
			expected:  "gcr.io/image:v1@" + testSHA256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reference.String())
		})
	}
}

func TestReference_Name(t *testing.T) {
	reference := &Reference{Registry: "gcr.io", Repository: "project/image", Tag: "v1", Digest: testSHA256}
	assert.Equal(t, "gcr.io/project/image", reference.Name())
}

func TestReference_WithDigest(t *testing.T) {
	reference := &Reference{Registry: "gcr.io", Repository: "image", Tag: "v1"}

	pinned, err := reference.WithDigest(testSHA256)
	require.NoError(t, err)
	assert.Equal(t, Reference{Registry: "gcr.io", Repository: "image", Digest: testSHA256}, *pinned)
	assert.Equal(t, "v1", reference.Tag, "the receiver is unchanged")
}

func TestReference_WithDigest_Invalid(t *testing.T) {
	reference := &Reference{Registry: "gcr.io", Repository: "image", Tag: "v1"}
	for _, digest := range []string{"", "sha256:abc", "sha1:" + strings.Repeat("a", 40)} {
		pinned, err := reference.WithDigest(digest)
		require.ErrorIs(t, err, ErrInvalidDigest, digest)
		assert.Nil(t, pinned)
	}
}

func TestReference_AttestationTag_Invalid(t *testing.T) {
	tests := []struct {
		name      string
		reference Reference
		err       error
	}{
		{name: "no digest", reference: Reference{Registry: "gcr.io", Repository: "image", Tag: "v1"}, err: ErrDigestRequired},
		{name: "invalid digest", reference: Reference{Registry: "gcr.io", Repository: "image", Digest: "sha256:abc"}, err: ErrInvalidDigest},
		// "sha512-<128 hex>.att" is longer than an OCI tag may be.
		{name: "sha512 digest", reference: Reference{Registry: "gcr.io", Repository: "image", Digest: testSHA512}, err: ErrInvalidDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, err := tt.reference.AttestationTag()
			require.ErrorIs(t, err, tt.err)
			assert.Empty(t, tag)
		})
	}
}

func TestReference_Validate(t *testing.T) {
	valid := Reference{Registry: "gcr.io", Repository: "image", Tag: "v1"}
	require.NoError(t, valid.Validate())

	tests := []struct {
		name      string
		reference Reference
		err       error
	}{
		{name: "no registry", reference: Reference{Repository: "image", Tag: "v1"}, err: ErrInvalidReference},
		{name: "no repository", reference: Reference{Registry: "gcr.io", Tag: "v1"}, err: ErrInvalidReference},
		{name: "no tag or digest", reference: Reference{Registry: "gcr.io", Repository: "image"}, err: ErrInvalidReference},
		{name: "invalid tag", reference: Reference{Registry: "gcr.io", Repository: "image", Tag: ".v1"}, err: ErrInvalidReference},
		{name: "invalid digest", reference: Reference{Registry: "gcr.io", Repository: "image", Digest: "sha256:zz"}, err: ErrInvalidDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.reference.Validate(), tt.err)
		})
	}
}

func TestReference_ManifestReference(t *testing.T) {
	assert.Equal(t, "v1", (&Reference{Tag: "v1"}).manifestReference())
	assert.Equal(t, testSHA256, (&Reference{Tag: "v1", Digest: testSHA256}).manifestReference())
}

func TestValidTag(t *testing.T) {
	for _, tag := range []string{"latest", "v1.0.0", "_build", "1.21-alpine", strings.Repeat("a", maxTagLength)} {
		assert.True(t, validTag(tag), tag)
	}
	for _, tag := range []string{"", "-bad", ".bad", "has space", "a/b", strings.Repeat("a", maxTagLength+1)} {
		assert.False(t, validTag(tag), tag)
	}
}
