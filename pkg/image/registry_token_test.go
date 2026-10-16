package image

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustURL parses raw, failing the test when it does not parse.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}

func TestBearerChallenge(t *testing.T) {
	tests := map[string]struct {
		values []string
		want   *challenge
	}{
		"quoted parameters": {
			values: []string{`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/app:pull,push"`},
			want:   &challenge{realm: mustURL(t, "https://auth.example/token"), service: "registry.example", scope: "repository:team/app:pull,push"},
		},
		"lower-case scheme, tokens and spaces": {
			values: []string{`bearer realm = "https://auth.example/token" , service=registry.example`},
			want:   &challenge{realm: mustURL(t, "https://auth.example/token"), service: "registry.example"},
		},
		"escaped quote": {
			values: []string{`Bearer realm="https://auth.example/token",scope="a\"b"`},
			want:   &challenge{realm: mustURL(t, "https://auth.example/token"), scope: `a"b`},
		},
		"after a basic challenge": {
			values: []string{`Basic realm="registry"`, `Bearer realm="https://auth.example/token"`},
			want:   &challenge{realm: mustURL(t, "https://auth.example/token")},
		},
		"basic only": {values: []string{`Basic realm="registry"`}},
		"none":       {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range tt.values {
				header.Add("WWW-Authenticate", value)
			}
			got, err := bearerChallenge(header)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBearerChallenge_Invalid(t *testing.T) {
	for name, value := range map[string]string{
		"no realm":            `Bearer service="registry.example"`,
		"http realm":          `Bearer realm="http://auth.example/token"`,
		"relative realm":      `Bearer realm="/token"`,
		"unterminated quote":  `Bearer realm="https://auth.example/token`,
		"dangling escape":     `Bearer realm="https://auth.example/token\`,
		"parameter without =": `Bearer realm`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := bearerChallenge(http.Header{"Www-Authenticate": {value}})
			require.ErrorIs(t, err, ErrRegistryAuth)
			assert.Nil(t, got)
		})
	}
}

func TestDecodeToken(t *testing.T) {
	for body, want := range map[string]string{
		`{"token":"t"}`:                    "t",
		`{"access_token":"a"}`:             "a",
		`{"token":"t","access_token":"a"}`: "t",
	} {
		token, err := decodeToken([]byte(body))
		require.NoError(t, err, body)
		assert.Equal(t, want, token, body)
	}
}

func TestDecodeToken_Invalid(t *testing.T) {
	for _, body := range []string{`{}`, `{"token":""}`, `not json`} {
		token, err := decodeToken([]byte(body))
		require.ErrorIs(t, err, ErrRegistryAuth, body)
		assert.Empty(t, token, body)
	}
}
