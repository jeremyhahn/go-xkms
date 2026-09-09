- **A partial config section keeps the defaults it omits (#114).** The
  loader seeded each section of `xkey.yaml` as one opaque viper default and
  decoded onto a zero `Config`, so the moment a file named a section, every
  key the file did not set in that section landed on its Go zero value
  instead of its `DefaultConfig()` value. A file containing only
  `policy: {min_pin_length: 8}` therefore loaded with `require_user_pin`,
  `require_so_pin` and `require_encrypted_storage` all `false`,
  `pin_max_attempts` 0 and `storage_type` empty: an administrator tightening
  one policy value silently switched off every other gate in the section,
  and a policy sealed after that point sealed the weakened one. The same
  shape affected all thirteen defaulted sections. The loader now decodes
  onto `DefaultConfig()`, so a section merges key by key: an omitted key
  keeps its default, an explicit value — an explicit `false` or `0`
  included — still wins, and a list the file sets replaces the default list
  outright. A deployment whose file names a section and, knowingly or not,
  relied on the omitted keys being zero gains the defaults on upgrade; for
  the `Require*` gates that is a tightening. Pinned by a per-section table
  test that compares the whole loaded `Config` against `DefaultConfig()`
  with the one set key applied.
