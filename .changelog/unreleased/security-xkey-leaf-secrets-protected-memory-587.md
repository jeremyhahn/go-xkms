- **Ten xkey leaf secrets move into protected memory, and one unimported
  duplicate PIV package is deleted** (#587, #41, #133). String-like secrets
  become `*secure.Secret`, byte secrets `*secure.Buffer`, always borrowed at
  the point of use rather than materialized as an unwipeable Go string: `usb.ImageConfig.Passphrase`
  (`formatLUKS` opens and borrows it for the whole LUKS format/unlock/lock
  sequence); `pwimport.ParsedEntry.Password` (the CSV, KDBX and XML parsers
  seal the parsed password immediately, and `ToStaticPassword` opens it only
  at the storage boundary); `authenticator.pinReadResult.pin`, whose
  `readPIN` now returns a `*secure.Buffer` the caller destroys, trimming
  surrounding whitespace on the raw bytes instead of a heap string; `gui/services.SudoElevator.password`,
  whose `Run` assembles the sudo stdin payload into a wipeable slice instead
  of an unwiped `bytes.Buffer`; `cmd/xkey/cmd.sharedKeyMaterial.KeyMaterial`,
  borrowed only for the duration of the phone share request; `cmd/xkey/cmd.FIDO2Config.PIN`,
  sealed once from viper and opened only to seed the authenticator's initial
  PIN; and `cmd/xkey/cmd.passwordListEntry.Password`, written to the CLI
  writer directly from the borrowed bytes rather than through a `%s` verb.
  `authenticator.UserVerificationResult.PIN` is deleted outright along with
  its only writers (`AutoGrantHandler`'s `simulatedPIN` and
  `NewAutoGrantHandlerWithPIN`): nothing in the tree ever read it. The
  unimported `xkey/pkg/pivcert` package, a stale duplicate of the canonical
  `pkg/pivcert`, is deleted. `scripts/secure-analyzer-allowlist.txt` drops
  the ten now-enforced entries; `make secure-analyzer` is green with no
  stale entries.
