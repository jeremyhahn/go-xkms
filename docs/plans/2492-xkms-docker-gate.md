# Plan: epic #2492, xkms docker gate (PR #2051)

Objective: the ci-images job runs on the bigdisk-docker pool (ruling 442) for a
push to main and a same-repository pull request, and on ubuntu-latest for every
other event; internal/buildgates/ci_image_digest_test.go pins that.

Slices:
1. ci-images runs-on routing + buildgates pin (done on #2051).
2. Main merge d55b1b73c7 (DS-8447): keep main's v1.34.1 ci-images header, take
   #2051's ruling 442 runs-on; results to follow.

Out of scope: other workflows, actionlint config, go.mod/go.sum, SPEC, ROADMAP.

## Results

- Merge d3dc3745a: ci-images keeps main's v1.34.1 `if:` (preflight verdict), runs-on is ruling 442; ci.yml differs from main only there.
- actionlint .github/workflows/ci.yml: pass.
- go test ./internal/buildgates/... (codec_cbor codec_json codec_msgpack): pass.
- make lint: pass.
