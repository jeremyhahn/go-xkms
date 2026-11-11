- `pkg/pkcs11/manager`: the test audit (#1794) removed tests that ran no
  package code or repeated a path another test pins: the host-probe smoke
  tests, the struct-field tests, `TestConnectionID`, `TestFileExists` and
  the stub's enumeration test.
