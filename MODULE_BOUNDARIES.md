# Module Boundaries

`packages/crypto-core` is the public review boundary for EncSend's extracted
browser-side cryptographic core.

## Included

- payload encryption and decryption in [src/encsendAesGcm.js](./src/encsendAesGcm.js)
- owner recovery profile primitives in [src/encsendOwnerProfile.js](./src/encsendOwnerProfile.js)
- encrypted owner key vault primitives in [src/encsendKeyVault.js](./src/encsendKeyVault.js)
- base64url helpers in [src/base64url.js](./src/base64url.js)
- deterministic fixtures in [test-vectors](./test-vectors)
- protocol and threat-model documentation in this directory

## Excluded

The following remain outside the public core and are still product adapters or
hosted-service concerns:

- DOM and view integration
- route wiring and controllers
- public-link challenge flows
- preview-gate enforcement
- OTP delivery and verification
- account and session handling
- audit logging
- queue, mail, and infrastructure operations
- deployment and runtime configuration

## Adjacent Private Layers

In the main product repository, the extracted core is consumed by private
feature modules that orchestrate product behavior around the cryptographic
primitives. Examples include:

- `resources/js/encsend/features/publicAndOwnerReadFlows.js`
- `resources/js/encsend/features/recoveryFlows.js`
- `resources/js/encsend/features/recoveryCenterManager.js`
- `resources/js/encsend/features/ownerProfileManager.js`
- `resources/js/encsend/features/keyVaultManager.js`

Those files are not part of the public crypto-core contract.

## Review Guidance

When publishing this package, describe it as:

- publicly reviewable cryptographic core
- protocol formats and deterministic test vectors
- not a complete audit of the hosted EncSend product

Do not describe this package alone as proof that every product-level security
property has been publicly reviewed.
