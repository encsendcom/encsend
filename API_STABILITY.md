# EncSend Crypto Core API Stability

## Stable Public Surface

The current intended public surface of `@encsend/crypto-core` is limited to the exported modules declared in [package.json](./package.json):

- `./base64url`
- `./encsendAesGcm`
- `./encsendOwnerProfile`
- `./encsendKeyVault`
- package root re-exports from `./src/index.js`

The current exported functions and constants in those modules are the compatibility boundary for the Open-Core package.

## Stability Rules

- Existing exported names must remain stable within a major version.
- Existing payload and wrap version strings are immutable contracts.
- Existing field names for a given version must not change in place.
- Existing cryptographic parameters for a given version must not change in place.
- Deterministic fixtures under `test-vectors/` are normative compatibility checks and must stay green.

## Breaking Changes

Any of the following requires a breaking-release decision and updated fixtures:

- changing a wire field name
- changing a version string
- changing KDF defaults for an existing format version
- changing AES-GCM AAD usage for an existing format version
- changing decrypted payload normalization behavior
- removing an exported function or constant

In practice, incompatible protocol changes should introduce a new format version instead of mutating an existing one.

## Not Public API

The following are not part of the public Open-Core API contract:

- files outside `packages/crypto-core`
- Blade or DOM integration
- request orchestration and fetch helpers
- route construction helpers
- local key-store implementations
- trusted-device UX
- preview-gate, OTP, and other product workflows

Those areas may be refactored independently as long as they continue to call the public crypto core correctly.
