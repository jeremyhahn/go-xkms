- **The authoritative DNS pre-check queries a configurable port (#140, item 14).**
  `CheckDNSFromAuthoritative` appended a literal `:53` to every nameserver the
  zone's NS records named, with no way to query a zone served elsewhere. The
  pre-check gains `WithNameserverPort`; `DefaultDNSPort` (`"53"`) is the
  defaults-layer value, an empty port keeps it, and a caller-supplied
  `WithNameserverLookup` still returns complete addresses untouched.
