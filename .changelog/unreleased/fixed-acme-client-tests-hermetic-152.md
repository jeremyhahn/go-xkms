- **`pkg/acme/client`'s tests no longer carry a path to Let's Encrypt
  production (#152).** `golang.org/x/crypto/acme` substitutes the Let's
  Encrypt directory for an empty `DirectoryURL`, so every test literal that
  omitted it was an outbound HTTPS call waiting for the validation ahead of
  it to regress; the ones that did reach the network failed on a ten-second
  TLS timeout instead of on the defect (CI run 7429), and one sibling test
  passed on that same timeout because its assertion could not tell the two
  apart. The remaining eleven literals point at a loopback port that refuses
  immediately, and a grep gate (`TestACMEClientLiteralsAreHermetic`) fails
  the suite on any `acme.Client` literal in the package's tests that omits
  `DirectoryURL`.
