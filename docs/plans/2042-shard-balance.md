# #2042 coverage shard balance

- Timing: PR #2042 run at f9a92b8316ff (19:16Z): shards 2-6 passed in 22-27 min; shard 1/6 still running at 20:41Z (85 min); main's make coverage lost its runner after 101 min. Cause: shard 1 runs its package slice plus every other make test part (shell, !frost, pkcs11, web, wailsjs), all under -p=1.
- Plan: time each extra part on the lane node; move the extras out of shard 1 into a 7th matrix entry (`make coverage-extras`) that writes its own profile; coverage-threshold downloads and merges every profile; -p=1 stays in every shard; buildgates test first, then the Makefile + ci.yml change.
- Results to follow.
