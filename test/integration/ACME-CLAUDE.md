# Integration Test Conventions

**ALWAYS** run integration tests in the project's devcontainer.

The project devcontainer should always have all dev, build and test dependencies installed.

## Packages with CLI support

The packages in this directory contain ONLY multi-protocol CLI tests that perform end-to-end testing of the CLI against the backend xkmsd service.

Each package is repsonsible for it's own CLI commands. For example, the kms package should contain a common command set that is used in table-driven tests that loop over each protocol that the CLI/SDK supports, and execute the command with all available permutations (ie., options flags) for the command to ensure it's working with all of the protocols in a consistent manner.

The CLI must implement the `sdk/go` in the root of the project for all operations. ALL of the modes must be tested in the multi-protocol table driven tests:

- embedded
- rest
- grpc
- quic
- mcp 
- unix (grpc over UDS)

**ALWAYS REMEMBER**

- Ensure integration tests are being performed E2E using the CLI binary in the project's devcontainer.

- Ensure the CLI is tested using a multi-protocol table-driven test convention using a common command set, that tests each command in against each protocol in a consistent mangger.

- Ensure that ALL permutations of commands are tested (ie., using all supported options flags, values, etc)

## Packages without CLI support

- Always test the upper-most abstraction for the package, for example, a "service" or "facade" object that implements the high level interface for the package, that allows us to test all of the layers of the package through it's user API.


## Test File Naming

**ALWAYS** use golang naming convention of $SOURCE_FILE_NAME_test.go, be sure to consolidate all tests related to the source file into a single $SOURCE_FILE_NAME_test.go to keep the codebase clean.

**NEVER** use generic names such as `_coverage_boost_test.go` `_additional_coverage_test.go` or otherwise.
