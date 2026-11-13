# go-xkms row table

One SPEC row = one row issue = one branch `row/<epic>-<slug>` = one lane
session = one PR (handbook `software/conventions/sdlc.md` §2b). Every open
issue is a row issue, sits under one, or is listed below as kept. The row's PR
closes its row issue and marks the row shipped in [docs/SPEC.md](../docs/SPEC.md).
Rows with no open work are not listed. Folded issues are closed and listed as a
checklist on their row issue.

## SPEC rows

| Row | Row issue | Status | Folded | Open PRs |
|---|---|---|---|---|
| web-console | #2082 | shipped | 0 | #2165, #2164, #2163, #2162, #2161, #2160, #2159, #2158, #2157, #2156, #2155, #2154, #2153, #2152, #2151, #2150, #2149, #2148, #2147, #2146, #2145, #2144, #2143, #2142, #2141, #2140, #2139, #2137, #2136, #2134, #2133, #2132, #2131, #2130, #2129, #2123, #2122, #2121, #2120, #2119, #2118 |
| tpm-policies | #2184 | in progress | 0 | #2124 |
| trust-roots | #2185 | in progress | 0 | #2095 |
| authz-token-perms | #2186 | planned | 0 | #2096 |
| trust-domain-grammar | #2187 | in progress | 0 | #2097 |
| authz-xkey-uid0 | #2188 | planned | 0 | #2098 |
| verifier-appraisal-seam | #2189 | planned | 0 | #2100 |
| release-signing-key | #2190 | planned | 0 | #2103 |
| optee-sealed-blob | #2191 | in progress | 0 | #2104 |
| xkey-ci-coverage | #2192 | planned | 0 | #2115 |
| ota-image-keys | #1778 | in progress | 0 | #2099 |
| device-security-event-evidence | #1817 | planned | 0 | #2105 |
| attestation-verifier | #1660 | in progress | 0 | #2101 |
| acme-issuance | #1667 | in progress | 1 | #2102 |
| qrdb-crypto-provider-seam | #2083 | in progress | 0 | #2106 |
| xkey-sdk-only | #2084 | planned | 0 | #2107, #2108, #2117 |
| acme | #2085 | planned | 0 | #2126 |
| authz-mtls-tenant | #2086 | planned | 0 | #2109 |
| dice-device-identity | #2087 | in progress | 0 | #2110 |
| continuous-attestation | #2088 | planned | 0 | #2111 |
| authz-tenant-ou | #2089 | planned | 0 | #2112 |
| authz-object-owner | #2090 | planned | 0 | #2113 |
| authz-device-onboarding | #2091 | planned | 0 | #2114 |
| tenant-status | #2092 | planned | 0 | #2138 |
| device-registry | #2093 | planned | 0 | #2127 |
| workload-identity | #2094 | in progress | 0 | #2128 |
| certificate-authority | #1820 | shipped | 2 | #2178, #2180, #2181 |
| webauthn | #1776 | shipped | 5 | #2182, #2169, #2179, #2173 |
| phone-verify-user | #1764 | in progress | 1 | #2177 |
| tpm2 | #1777 | shipped | 0 | #2176 |
| ssh-sessions | #1808 | shipped | 0 | #2170 |
| ssh-keys | #1807 | shipped | 0 | #2174 |
| ca | #781 | planned | 0 | #2166 |
| fido2-ctap2 | #2052 | shipped | 0 | none |
| password-vault-usb | #1775 | planned | 0 | none |
| transparency-log | #1601 | in progress | 0 | none |
| image-signing | #1598 | in progress | 0 | none |
| hsm-device-protocol | #1573 | future | 0 | none |
| release-engineering | #1082 | shipped | 5 | #2028, #2171 |

## Seam rows (cross-repo)

| Seam | Row issue | Folded | Open PRs |
|---|---|---|---|
| go-qrdb and go-enclave dependency integration (re-pin, retire GuardedBuffer) | #1995 | 2 | none |
| keystore seam for go-quicbaas (#2155): key-name uniqueness, ListKeyVersions re-export | #1927 | 1 | none |
| go-quicbaas store migrators (WebAuthn credentials, SSH stores) | #1801 | 1 | #1961, #1962 |
| device-generic xkms: AVR backend to trusted-firmware, xkey reaches AVR through it | #1491 | 1 | none |
| cross-domain key lock on the ELE key store (trusted-firmware#50 A3) | #1802 | 0 | none |

## Kept outside the rows

| Issue | Class | Why |
|---|---|---|
| #1846 | owner | Test-suite audit, ruling 273; not a SPEC row; #1659 folded in. PRs #2079, #2135, #2125, #2116, #2172, #2068 fold into one PR |
| #1384 | owner | PR test code reaches the runner host's Docker daemon (runner infrastructure) |
| #1385 | owner | Private-module token in every CI job's environment (runner infrastructure) |
| #1933 | main-fix | GO-2026-6911 reachable through go-xkms |
| #1934 | main-fix | deps-check red on spf13/pflag |
| #1815 | CI-red | pkcs11 module test timeout on a loaded runner (PR #2175) |
| #2167 | CI-red | Node 26 localStorage shadows jsdom (PR #2168) |

## Main-fix PRs

#2183 is the active main-fix row (CA shepherd); it supersedes #2042, #2071,
#2080 and #2081. #2020 is an earlier main-fix draft.

## Cross-row aggregates

#2075 (F1 CI), #2076 (F2 deps), #2077 (F3 CA, fido2, ACME), #2078 (F4
attestation and SPEC features) and #1975 (train t1873) carry members of several
rows. Each row lands through its own row PR; these branches stay as sources
until their members are carried.
