# shellcheck shell=sh disable=SC2034
#
# Tool pins: the one place every tool version and download checksum lives
# (handbook ci-standard.md). The Makefile includes this file and the
# devcontainer Dockerfile (build/docker/devcontainer/Dockerfile) sources it,
# so the image CI runs and the tools `make` installs on a host never drift.
#
# Plain KEY=value lines only: no quotes, no spaces, no shell expansion. Make
# and sh must both read the same values. A version bump changes the matching
# SHA-256 in the same commit; every download is checked against it.

# Base image: the Go toolchain, pinned by digest.
GO_IMAGE=golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110

# Go-installed gate tools (module proxy checksums cover them).
GOLANGCI_VERSION=v2.14.0
ACTIONLINT_VERSION=v1.7.12
GOSEC_VERSION=v2.29.0
XTOOLS_VERSION=v0.52.0
GOVULNCHECK_VERSION=v1.8.0
PROTOBUF_GO_VERSION=v1.36.12
PROTOC_GEN_GO_GRPC_VERSION=v1.6.2

# Go-installed devcontainer conveniences.
DELVE_VERSION=v1.27.2
GOPLS_VERSION=v0.24.0
GOMODIFYTAGS_VERSION=v1.17.0
GOTESTS_VERSION=v1.9.0
IMPL_VERSION=v1.5.0
STATICCHECK_VERSION=v0.8.2

# Release binaries.
TRIVY_VERSION=v0.75.0
TRIVY_SHA256_LINUX_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
TRIVY_SHA256_LINUX_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
GRPCURL_VERSION=1.8.9
GRPCURL_SHA256_LINUX_AMD64=a422d1e8ad854a305c0dd53f2f2053da242211d3d1810e7addb40a041e309516
GRPCURL_SHA256_LINUX_ARM64=1303f4c1c6667f31b80efbe483875c749c94c8cb0d8b631bd64179f0b140714d
# actionlint runs shellcheck over every run: script, and its findings differ by
# release: bookworm's apt shellcheck (0.9.0) reports an SC2015 that 0.11.0 does
# not, in the fleet's code-review.yml (#1558). The image carries this release.
SHELLCHECK_VERSION=v0.11.0
SHELLCHECK_SHA256_LINUX_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_LINUX_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
NODE_VERSION=v20.20.2
NODE_SHA256_LINUX_AMD64=df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d
NODE_SHA256_LINUX_ARM64=73093db209e4e9e09dd7d15a47aeaab1b74833830df03efa5f942a1122c5fa71

# Native libraries built from source (release tarballs).
LIBFIDO2_VERSION=1.16.0
LIBFIDO2_SHA256=8c2b6fb279b5b42e9ac92ade71832e485852647b53607c43baaafbbcecea04e4
LIBTPMS_VERSION=0.10.1
LIBTPMS_SHA256=ebc24f3191d90f6cf0b4d4200cd876db4bd224b3c565708bbea0a82ee275e0fb
PKCS11_PROVIDER_OSSL3_VERSION=0.6
PKCS11_PROVIDER_OSSL3_SHA256=f20e85c1e1ae819ddb440bdba47fa3b44943aaebaf05e59b04630126497a6ed6
PKCS11_PROVIDER_OSSL4_VERSION=1.2.0
PKCS11_PROVIDER_OSSL4_SHA256=36a2f13859f3e2a9c74d1d4064f8d406689b0201e25968aba952010ed73bfec2
OPENSSL_VERSION=4.0.1
OPENSSL_SHA256=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09
OPENSSH_VERSION=10.4p1
OPENSSH_SHA256=ef6026dd2aea8d56059638d5d3262902c892ceba9f88395835e0d06d3fb63238
