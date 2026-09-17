- **The ACME client silently ignored a server's `Retry-After` backoff whenever
  the value overflowed a `time.Duration` or used either of the two HTTP-date
  forms besides IMF-fixdate** (#564). `parseRetryAfter` returned a
  `time.Duration` and `RateLimitedTransport.RoundTrip` gated on `duration > 0`,
  so three separate inputs collapsed to "no hold-off" and the client kept
  hammering a server that had just answered `429`: a digits-only value above
  `math.MaxInt64 / int64(time.Second)` (~9.22e9) wrapped negative in
  `time.Duration(seconds) * time.Second` — measured, `"10000000000"` yielded
  `-2346317h47m53s`; the hand-rolled `parseInt` had no overflow check, so
  `"99999999999999999999999"` wrapped to `200376420520689663` rather than being
  detected as out of range; and `time.Parse(time.RFC1123, ...)` rejected the
  RFC 850 and asctime dates that RFC 9110 §5.6.7 requires a recipient to
  accept, returning `0`.

  The parser now follows RFC 9110 §10.2.3: delta-seconds via
  `strconv.ParseUint` (digits only, clamping both the `ErrRange` case and any
  value beyond the representable duration), HTTP-date in all three forms via
  `http.ParseTime`, and an already-elapsed date rejected in the parser instead
  of incidentally by the caller. It returns the absolute instant rather than a
  duration, so the transport hands it to the existing `SetRetryAfterTime`
  unrounded — no round trip through `time.Until` and a second `time.Now()`. The
  parser's clamp composes with `storeRetryDeadline`'s year-2262 clamp, so a
  far-future deadline stays representable and reads back as blocked. The
  now-unused `parseInt` and its test are removed; the deadline storage, the
  overflow clamp and the compare-and-swap clearing in `waitRetryAfter` / `Allow`
  are unchanged and still covered by `rate_limiter_deadline_test.go`.
  `pkg/acme/client/rate_limiter.go`, `rate_limiter_test.go`,
  `docs/acme/client.md`. Verified by table-driven parser tests over
  delta-seconds, each of the three date forms, an elapsed date, an equal-to-now
  date, both overflow paths and malformed input, plus transport tests that an
  HTTP-date header stores the named instant exactly and an unparseable one
  installs no hold-off.
