package cmd

import "time"

// slowStoreWait is the ceiling of the Eventually and time.After waits in the
// OIDC command tests. It is a ceiling for runners whose storage syncs take
// seconds (issue #2246), never a sleep: a passing condition returns at its
// first true poll, so a fast runner never waits for it.
const slowStoreWait = 60 * time.Second
