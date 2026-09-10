- **xkey: `XKEY_*` environment variables reach every leaf key (#140, xkey mechanism gap).**
  The loader registered each config section as one opaque struct default, so
  viper knew `xkmsd` but not `xkmsd.address`, and `AutomaticEnv`, which only
  consults the environment for keys viper knows, never looked `XKEY_XKMSD_ADDRESS`
  up; no `XKEY_` variable took effect, while the configuration reference said
  all of them did, and the one test hedged between the two outcomes. The loader
  now walks the config struct and registers every leaf with its default and its
  `XKEY_<KEY>` binding, so environment wins over file wins over default at leaf
  granularity, lists of scalars split on commas, and an environment value is
  validated like a file value. `backends.local`, `backends.remote`,
  `backends.defaults` and `fido2.extensions` cannot be expressed by one
  variable; a variable set for one of them fails the load instead of being
  ignored.
