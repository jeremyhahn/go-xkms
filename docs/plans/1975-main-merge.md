# 1975: merge main d55b1b73c7 into train/t1873

- Merge: main d55b1b73c7 (ci-template v1.34.1, Go 1.27.4, GOPRIVATE compose form) into train/t1873; main's template and toolchain layer wins, the train's own work is carried.
- Checks: actionlint, go build ./..., buildgates tests with the codec tags, make lint.

## Resolution

- Dockerfiles (13): main's golang:1.27.4-bookworm base; the train's apt-retries.conf COPY step (go-xkms#342) kept after each FROM.
- ci.yml: main's v1.34.1 file whole, with these train items re-added:
  - the nightly cron on Friday night only, '0 5 * * 6' (#1876);
  - the Integration job as a fail-fast-off matrix over IT_SHARDS 1-6, timeout 90, IT_PROJECT per shard, make integration-test-shard (#1870), under main's preflight needs, verdict if and bigdisk-docker runs-on; the header deviation line with it;
  - the xkey coverage profiles and make coverage-check in the hosted xkey tests step (xkey-ci-coverage);
  - --secret-config trivy-secret.yaml on the integration image scan, with its comment.
- Not carried: the six-job Devcontainer split (dc-lint ... dc-trivy, #1871). v1.34.1 is one image job, and the brief puts that job in main's layer. TestCIImageDigest_RevertedConsumerFails goes back to main's form (reverts the image job).

## Results

- actionlint: pass. go build ./...: pass. make lint: pass (0 issues on every module and tag set).
- buildgates: TestCIImageDigest_RevertedConsumerFails failed at ci_image_digest_test.go:452 (no dc-* job); after the test(buildgates) commit, pass.
- The train still carries over main: 302 files changed, 18907 insertions, 1784 deletions; most in pkg/ (with pkg/server, pkg/api), .changelog/unreleased, test/integration/api, sdk/go and xkey.
