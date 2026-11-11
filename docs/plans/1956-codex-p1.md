Findings: (P1) grpc Connect publishes plaintextChannel/dialedTarget/credsOpt before grpc.NewClient succeeds, so a failed TLS reconnect leaves the old plaintext client classified as TLS; (P1) SignImage admits one OpSign use but signs twice (CSR + DSSE), bypassing MaxUsageCount.
Plan: test(grpc) failed reconnect then credentialed SignImage refused, fix(grpc) publish client and security state together only after NewClient succeeds; test(xkms) MaxUsageCount=1 SignImage fails and records <=1 use, =2 succeeds and records 2, fix(xkms) admit and charge both signatures.
Results to follow.
