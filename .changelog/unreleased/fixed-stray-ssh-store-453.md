- **Removed a stray xkey SSH store from the repository root (#453).** A manual
  `xkey ssh` run with the data directory set to `ssh` had written its profile
  and key-record store to `ssh/ssh/` inside the checkout, and the directory was
  committed. The two records were a host profile carrying a LAN address and an
  account name, and a key record holding only a public key and a backend
  reference — no private material. Nothing in the build or the tests referenced
  the directory. `/ssh/` at the repository root is now ignored so a local run
  cannot recommit it.
