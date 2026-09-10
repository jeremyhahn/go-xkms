- **`DeriveNoiseAddr` no longer mangles IPv6 literals (#140).** The Noise
  bootstrap address derived from a server URL was cut at the last colon, so
  `https://[fd00::1]` became `[fd00::8445` and a userinfo prefix survived
  into the dial. The host is now taken from a parsed URL and joined with
  `DefaultNoisePort`; a bare IP literal, bracketed or not, is joined whole; a
  URL with no host derives nothing and surfaces as `ErrServerURLRequired`.
