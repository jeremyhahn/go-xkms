package image

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// maxTokenSize bounds a token response read from a registry's auth realm.
const maxTokenSize = 64 << 10

// challenge is a registry's Bearer challenge (RFC 6750 section 3): where
// the OCI distribution token flow fetches a token, and for what.
type challenge struct {
	realm   *url.URL
	service string
	scope   string
}

// bearerChallenge returns the Bearer challenge among header's
// WWW-Authenticate values, or nil when it carries none. A Bearer challenge
// without an https realm is refused: the realm receives the basic
// credentials.
func bearerChallenge(header http.Header) (*challenge, error) {
	for _, value := range header.Values("WWW-Authenticate") {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		params, ok := authParams(rest)
		if !ok {
			return nil, &errs.Detail{Err: ErrRegistryAuth, Detail: "malformed Bearer challenge"}
		}
		realm, err := url.Parse(params["realm"])
		if err != nil || realm.Scheme != "https" || realm.Host == "" {
			return nil, &errs.Detail{Err: ErrRegistryAuth, Detail: "Bearer challenge realm is not an https URL"}
		}
		return &challenge{realm: realm, service: params["service"], scope: params["scope"]}, nil
	}
	return nil, nil
}

// authParams parses the comma-separated auth-params of a challenge
// (RFC 9110 section 11.2): name=token or name="quoted-string". Names are
// case-insensitive and returned lower-case.
func authParams(s string) (map[string]string, bool) {
	params := map[string]string{}
	for {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			return params, true
		}
		name, rest, ok := strings.Cut(s, "=")
		if !ok {
			return nil, false
		}
		rest = strings.TrimLeft(rest, " \t")
		var value string
		if quoted, isQuoted := strings.CutPrefix(rest, `"`); isQuoted {
			if value, rest, ok = unquote(quoted); !ok {
				return nil, false
			}
		} else {
			value, rest, _ = strings.Cut(rest, ",")
		}
		params[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		s = rest
	}
}

// unquote reads a quoted-string's content up to its closing quote,
// resolving backslash escapes, and returns it and what follows the quote.
func unquote(s string) (string, string, bool) {
	var value strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return value.String(), s[i+1:], true
		case '\\':
			i++
			if i == len(s) {
				return "", "", false
			}
		}
		value.WriteByte(s[i])
	}
	return "", "", false
}

// fetchToken requests a token for the challenge's service and scope from
// its realm, with the client's basic credentials when it has them.
func (c *registryClient) fetchToken(ctx context.Context, ch *challenge) (string, error) {
	target := *ch.realm
	query := target.Query()
	if ch.service != "" {
		query.Set("service", ch.service)
	}
	if ch.scope != "" {
		query.Set("scope", ch.scope)
	}
	target.RawQuery = query.Encode()

	resp, err := c.send(ctx, &request{method: http.MethodGet, url: &target, accept: []string{"application/json"}, realm: true}, maxTokenSize)
	if err != nil {
		return "", err
	}
	if resp.status != http.StatusOK {
		return "", &errs.Joined{Lead: ErrRegistryAuth, Cause: statusError(resp)}
	}
	return decodeToken(resp.body)
}

// decodeToken returns the token of a token response: its token field, or
// the OAuth 2.0 access_token some realms answer with instead.
func decodeToken(body []byte) (string, error) {
	var reply struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return "", &errs.Joined{Lead: ErrRegistryAuth, Detail: "token response", Cause: err}
	}
	if reply.Token != "" {
		return reply.Token, nil
	}
	if reply.AccessToken != "" {
		return reply.AccessToken, nil
	}
	return "", &errs.Detail{Err: ErrRegistryAuth, Detail: "token response carries no token"}
}
