- **The xkey PKCS#11 embedded transport now reports an exported key's
  algorithm family through the one canonical resolution instead of a private
  formatter** (#402, split from #336). `xkey/pkg/pkcs11`'s `getAlgorithmString`
  was the fourth copy of the family question #336 reduced to one method, and
  the last one outside the root module. It was kept out of #336's scope on the
  possibility that it was a PKCS#11-edge mapping whose spellings a consumer
  depended on; it is not. Nothing at that edge reads the field — the module's
  only consumer of the response (`pkg/pkcs11/module/module.go`
  `secretKeyValue`) takes `KeyMaterial` and ignores `KeyType`, and the value is
  never compared against a `CKK_*` or any other constant — while the
  daemon-side producer of the same wire field (`pkg/xkms/servicer_key.go`)
  answers with the key's symmetric algorithm, with neither the `"unknown"`
  default nor the `KeyTypeSecret` gate the xkey copy carried. Those two
  branches were unreachable at the one call site anyway: a backend releases raw
  material only for a single-family symmetric key, refusing a descriptor that
  names two families (#158) and refusing anything asymmetric outright. So the
  formatter is deleted and `ExportKeyMaterial` calls
  `KeyAttributes.AlgorithmString()`, whose agreement with `ID()` is already
  pinned in `pkg/types`. The one reachable output is unchanged; the divergence
  that could have reappeared is gone. `xkey/pkg/pkcs11/service.go`,
  `xkey/pkg/pkcs11/service_exportkeymaterial_test.go`. The new tests assert the
  reported family against a literal and against the family segment of the key's
  own `ID()`, so a transport that grows a private opinion again fails rather
  than agreeing with itself, and cover the refusals that produce no family at
  all.
