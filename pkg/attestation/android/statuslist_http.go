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

package android

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// DefaultStatusListTimeout bounds one fetch of the status list.
const DefaultStatusListTimeout = 10 * time.Second

// maxDeltaSeconds is the value RFC 9111 §1.2.2 substitutes for a
// delta-seconds value too large to represent.
const maxDeltaSeconds = 2147483648

var (
	// ErrInvalidStatusListURL is returned for a status list URL that is not
	// an absolute http or https URL.
	ErrInvalidStatusListURL = errors.New("android: invalid attestation status list URL")

	// ErrStatusListHTTPStatus is the cause of an unavailable list whose
	// fetch was answered with a status other than 200 OK.
	ErrStatusListHTTPStatus = errors.New("android: attestation status list fetch was not 200 OK")

	// ErrStatusListStale is the cause of an unavailable list whose response
	// was already past its freshness lifetime when it arrived, even after
	// a request forcing revalidation (RFC 9111 §4.2, §5.2.1.4).
	ErrStatusListStale = errors.New("android: attestation status list response is stale")
)

// HTTPStatusListOptions configures an HTTPStatusList. The zero value
// fetches Google's list with the default bounds.
type HTTPStatusListOptions struct {
	// URL is the list's address. Empty means GoogleStatusListURL.
	URL string

	// Client sends the request. Nil means a client with no other timeout
	// than Timeout.
	Client *http.Client

	// Timeout bounds one fetch, response body included. Zero means
	// DefaultStatusListTimeout.
	Timeout time.Duration

	// MaxBytes bounds the response body. Zero means
	// DefaultMaxStatusListBytes.
	MaxBytes int64

	// Now is the clock freshness is measured on. Nil means time.Now.
	Now func() time.Time
}

// HTTPStatusList fetches the status list over HTTP and keeps it for as
// long as the response's caching headers allow, so a network request is
// not made for every verification (§Certificate revocation status list:
// "The Cache-Control header in the HTTP response determines how often to
// check for updates").
//
// A list past its freshness lifetime is never used: when it cannot be
// fetched again, Current fails with ErrStatusListUnavailable and the
// verification fails closed. §Certificate revocation status list calls the
// check "critical", and §Before you begin says not to fully trust an
// attestation unless every certificate is valid; a list the server no
// longer vouches for cannot show that. RFC 9111 §4.2.4 only permits a
// cache to serve stale responses, it never requires it, so refusing them
// conforms. Hosts that cannot reach the list configure a StatusList loaded
// from a file instead.
type HTTPStatusList struct {
	url      string
	client   *http.Client
	timeout  time.Duration
	maxBytes int64
	now      func() time.Time

	cached atomic.Pointer[cachedStatusList]
	// fetch serializes refreshes so concurrent verifications of a stale
	// list make one request; the fresh path reads cached without it.
	fetch sync.Mutex
}

// cachedStatusList is a fetched list and the instant it stops being fresh.
type cachedStatusList struct {
	list       *StatusList
	freshUntil time.Time
}

var _ StatusListSource = (*HTTPStatusList)(nil)

// NewHTTPStatusList returns an HTTP status list source. It makes no
// request: the first Current call fetches.
func NewHTTPStatusList(opts HTTPStatusListOptions) (*HTTPStatusList, error) {
	h := &HTTPStatusList{
		url:      opts.URL,
		client:   opts.Client,
		timeout:  opts.Timeout,
		maxBytes: opts.MaxBytes,
		now:      opts.Now,
	}
	if h.url == "" {
		h.url = GoogleStatusListURL
	}
	if h.client == nil {
		h.client = &http.Client{}
	}
	if h.timeout <= 0 {
		h.timeout = DefaultStatusListTimeout
	}
	if h.maxBytes <= 0 {
		h.maxBytes = DefaultMaxStatusListBytes
	}
	if h.now == nil {
		h.now = time.Now
	}

	u, err := url.Parse(h.url)
	if err != nil {
		return nil, &errs.Detail{Err: ErrInvalidStatusListURL, Detail: err.Error()}
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, &errs.Detail{Err: ErrInvalidStatusListURL, Detail: h.url}
	}
	return h, nil
}

// URL returns the address the list is fetched from.
func (h *HTTPStatusList) URL() string {
	return h.url
}

// Current returns the cached list while it is fresh, else fetches it.
func (h *HTTPStatusList) Current() (*StatusList, error) {
	if list := h.fresh(); list != nil {
		return list, nil
	}

	h.fetch.Lock()
	defer h.fetch.Unlock()
	// Another caller may have refreshed while this one waited.
	if list := h.fresh(); list != nil {
		return list, nil
	}

	list, freshUntil, err := h.download(false)
	if errors.Is(err, ErrStatusListStale) {
		// A cache on the path answered with a list already past its
		// freshness lifetime (RFC 9111 §4.2). Ask once more with
		// validation forced (§5.2.1.4); a list still stale is refused.
		list, freshUntil, err = h.download(true)
	}
	if err != nil {
		return nil, &StatusListUnavailableError{Source: h.url, Cause: err}
	}
	h.cached.Store(&cachedStatusList{list: list, freshUntil: freshUntil})
	return list, nil
}

// fresh returns the cached list if it is still fresh, else nil.
func (h *HTTPStatusList) fresh() *StatusList {
	c := h.cached.Load()
	if c == nil || !h.now().Before(c.freshUntil) {
		return nil
	}
	return c.list
}

// download fetches and parses the list, returning when it stops being
// fresh. A response that is stale on arrival fails with ErrStatusListStale.
// revalidate sends Cache-Control: no-cache, so that no cache on the path
// answers from a stored response without validating it with the origin
// (RFC 9111 §5.2.1.4).
func (h *HTTPStatusList) download(revalidate bool) (_ *StatusList, _ time.Time, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")
	if revalidate {
		req.Header.Set("Cache-Control", "no-cache")
	}

	requested := h.now()
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, &errs.Detail{Err: ErrStatusListHTTPStatus, Detail: resp.Status}
	}
	if resp.ContentLength > h.maxBytes {
		return nil, time.Time{}, &errs.Detail{Err: ErrStatusListTooLarge, Detail: fmt.Sprintf("content length %d over %d bytes", resp.ContentLength, h.maxBytes)}
	}
	data, err := readBounded(resp.Body, h.maxBytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	list, err := ParseStatusList(data)
	if err != nil {
		return nil, time.Time{}, err
	}

	received := h.now()
	until, stale := freshUntil(resp.Header, requested, received)
	if stale {
		return nil, time.Time{}, &errs.Detail{Err: ErrStatusListStale, Detail: fmt.Sprintf("not fresh on arrival (Cache-Control %q, Expires %q, Age %q)", resp.Header.Get("Cache-Control"), resp.Header.Get("Expires"), resp.Header.Get("Age"))}
	}
	return list, until, nil
}

// freshUntil is the instant a response stops being fresh: the time it was
// received plus its freshness lifetime less its age at that time (RFC 9111
// §4.2: response_is_fresh = freshness_lifetime > current_age, the lifetime
// per §4.2.1 and the age per §4.2.3, whose resident_time is zero on
// receipt). stale reports a response that carries freshness information
// and is not fresh by that comparison: one served by a cache with an Age
// beyond its max-age, a max-age of 0, or an Expires in the past, whether or
// not it may be cached. A response with no freshness information is not
// stale, nor is a fresh one marked no-store or no-cache; either answers this
// request and is never reused.
func freshUntil(header http.Header, requested, received time.Time) (_ time.Time, stale bool) {
	lifetime, explicit, reusable := freshnessLifetime(header, received)
	if !explicit {
		return received, false
	}
	age := initialAge(header, requested, received)
	if lifetime <= age {
		return received, true
	}
	if !reusable {
		return received, false
	}
	return received.Add(lifetime - age), false
}

// freshnessLifetime implements RFC 9111 §4.2.1 for a private cache. explicit
// reports whether the response carries freshness information at all, a
// max-age (§5.2.2.1) or an Expires (§5.3), even an invalid one: §5.3 reads
// an invalid Expires as a time in the past, and §4.2.1 has a response with
// invalid freshness information considered stale. max-age wins over
// Expires; s-maxage applies to shared caches only.
//
// no-store (§5.2.2.5) and no-cache (§5.2.2.4) forbid reuse without
// validation, which this source does not do, so they clear reusable: the
// response answers this request only. They do not remove its freshness
// information, so a response that has outlived its max-age or Expires is
// still stale and a revocation list past its expiry is never accepted. With
// neither max-age nor Expires the list is not reused either: §4.2.2 permits
// heuristic freshness but does not require it, and a revocation list is
// not something to guess the freshness of.
func freshnessLifetime(header http.Header, received time.Time) (_ time.Duration, explicit, reusable bool) {
	maxAge, hasMaxAge := int64(0), false
	reusable = true
	for _, field := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(field, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache":
				reusable = false
			case "max-age":
				// §4.2.1: the first occurrence is used, in this field
				// or an earlier one, so a later one cannot extend it.
				if hasMaxAge {
					continue
				}
				seconds, ok := parseDeltaSeconds(value)
				if !ok {
					// An invalid max-age is a response that is not fresh:
					// a lifetime of zero, which no age is below.
					seconds = 0
				}
				maxAge, hasMaxAge = seconds, true
			}
		}
	}
	if hasMaxAge {
		return time.Duration(maxAge) * time.Second, true, reusable
	}

	expiresField := header.Get("Expires")
	if expiresField == "" {
		return 0, false, reusable
	}
	// §5.3: an invalid Expires, "0" in particular, is a time in the past.
	expires, err := http.ParseTime(expiresField)
	if err != nil {
		return 0, true, reusable
	}
	date := received
	if parsed, err := http.ParseTime(header.Get("Date")); err == nil {
		date = parsed
	}
	return expires.Sub(date), true, reusable
}

// initialAge implements the corrected_initial_age of RFC 9111 §4.2.3: the
// larger of the apparent_age the Date field implies and the corrected
// age_value, the Age field (§5.1), or 0 without a valid one, plus the
// response_delay of the request's round trip.
func initialAge(header http.Header, requested, received time.Time) time.Duration {
	var apparentAge time.Duration
	if date, err := http.ParseTime(header.Get("Date")); err == nil {
		apparentAge = max(received.Sub(date), 0)
	}

	var ageValue time.Duration
	if seconds, ok := parseDeltaSeconds(header.Get("Age")); ok {
		ageValue = time.Duration(seconds) * time.Second
	}
	correctedAge := ageValue + received.Sub(requested)
	return max(apparentAge, correctedAge)
}

// parseDeltaSeconds parses an RFC 9111 §1.2.2 delta-seconds value, a
// non-negative decimal integer, saturating at 2147483648. A quoted value
// is accepted for max-age, as §5.2 asks of recipients.
func parseDeltaSeconds(value string) (int64, bool) {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return 0, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds > maxDeltaSeconds {
		// Every character is a digit, so the only failure is overflow.
		return maxDeltaSeconds, true
	}
	return seconds, true
}
