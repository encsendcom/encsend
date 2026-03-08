# EncSend Crypto Core Protocol

## Scope

This document describes the cryptographic payload formats implemented by `@encsend/crypto-core`.

It covers:

- browser-side secret payload encryption
- owner recovery profile encryption
- owner-wrapped secret and request keys
- encrypted owner key-vault backups

It does not define product-level behavior such as OTP challenges, preview gates, audit logging, routing, or account/session handling.

## Encoding Conventions

- Symmetric key material is 32 random bytes encoded as base64url without padding.
- AES-GCM IVs are 12 bytes.
- HKDF and PBKDF2 salts are 16 bytes.
- AES-GCM authentication tag length is 128 bits.
- UTF-8 is used for text payloads.

## Secret Payloads

### Legacy Payload: `encsend-aesgcm-v1`

Legacy payloads are directly encrypted with the link key material.

Expected wire fields:

```json
{
  "encryption_version": "encsend-aesgcm-v1",
  "encryption_algorithm": "AES-GCM",
  "encryption_iv": "<base64url>",
  "encrypted_payload": "<base64url>"
}
```

The v1 format is supported for decryption compatibility only.

### Wrapped Payload: `encsend-aesgcm-wrap-v2`

The current payload flow is:

1. Generate a random 32-byte payload key.
2. Encrypt the plaintext with AES-GCM using that payload key.
3. Derive a link-wrap key from the public link fragment key via HKDF-SHA-256.
4. Encrypt the payload key with the derived link-wrap key.
5. Optionally encrypt that wrapped payload key again with a password-derived AES key.

The browser API returns camelCase fields:

```json
{
  "encryptedPayload": "<base64url>",
  "encryptedKey": "<base64url>",
  "encryptionVersion": "encsend-aesgcm-wrap-v2",
  "encryptionAlgorithm": "AES-GCM",
  "encryptionIv": "<base64url>",
  "encryptionMeta": {
    "payload_iv_length": 12,
    "payload_tag_length": 128,
    "encoding": "utf-8",
    "key_material_encoding": "base64url",
    "link_wrap": {
      "kdf": "HKDF-SHA-256",
      "info": "encsend/link-wrap/v2",
      "salt": "<base64url>",
      "iv": "<base64url>",
      "tag_length": 128
    },
    "password_wrap": {
      "enabled": true
    }
  }
}
```

The wire format used by the application normalizes the outer field names to snake_case:

```json
{
  "encryption_version": "encsend-aesgcm-wrap-v2",
  "encryption_algorithm": "AES-GCM",
  "encryption_iv": "<base64url>",
  "encrypted_payload": "<base64url>",
  "encrypted_key": "<base64url>",
  "encryption_meta": {
    "payload_iv_length": 12,
    "payload_tag_length": 128,
    "encoding": "utf-8",
    "key_material_encoding": "base64url",
    "link_wrap": {
      "kdf": "HKDF-SHA-256",
      "info": "encsend/link-wrap/v2",
      "salt": "<base64url>",
      "iv": "<base64url>",
      "tag_length": 128
    },
    "password_wrap": {
      "enabled": false
    }
  }
}
```

#### Link Wrap

- KDF: `HKDF-SHA-256`
- Context string: `encsend/link-wrap/v2`
- Input keying material: the 32-byte link fragment key
- Output key: AES-256-GCM key

#### Optional Password Wrap

When enabled, the already link-wrapped payload key is wrapped again using:

- KDF: `PBKDF2-SHA-256`
- Iterations: `210000`
- Output key: AES-256-GCM key

The current password-wrap metadata shape is:

```json
{
  "enabled": true,
  "kdf": "PBKDF2-SHA-256",
  "iterations": 210000,
  "salt": "<base64url>",
  "iv": "<base64url>",
  "tag_length": 128
}
```

## Owner Recovery Profile

The owner recovery profile stores the owner master key encrypted under a user-supplied recovery passphrase.

- Version: `encsend-owner-profile-v1`
- Algorithm: `AES-GCM`
- KDF: `PBKDF2-SHA-256`
- Additional authenticated data: the version string itself

Wire format:

```json
{
  "profile_version": "encsend-owner-profile-v1",
  "encryption_algorithm": "AES-GCM",
  "encrypted_master_key": "<base64url>",
  "encryption_iv": "<base64url>",
  "kdf": {
    "name": "PBKDF2-SHA-256",
    "iterations": 260000,
    "salt": "<base64url>"
  },
  "metadata": {
    "created_at": "<iso8601>",
    "format": "encsend-owner-master-key"
  }
}
```

Valid decrypt-time iteration bounds enforced by the current implementation are `120000` through `1000000`.

## Owner-Wrapped Request Keys

Request keys can be wrapped directly with the owner master key.

- Version: `encsend-owner-rk-wrap-v1`
- Algorithm: `AES-GCM`
- Additional authenticated data: `encsend-owner-rk-wrap-v1`

Wire format:

```json
{
  "key_version": "encsend-owner-rk-wrap-v1",
  "wrapping_algorithm": "AES-GCM",
  "wrapped_request_key": "<base64url>",
  "wrapping_iv": "<base64url>",
  "wrapping_meta": {
    "tag_length": 128,
    "encoding": "base64url"
  }
}
```

## Owner-Wrapped Secret Keys

Secret keys can be wrapped directly with the owner master key.

- Version: `encsend-owner-sk-wrap-v1`
- Algorithm: `AES-GCM`
- Additional authenticated data: `encsend-owner-sk-wrap-v1`

Wire format:

```json
{
  "key_version": "encsend-owner-sk-wrap-v1",
  "wrapping_algorithm": "AES-GCM",
  "wrapped_secret_key": "<base64url>",
  "wrapping_iv": "<base64url>",
  "wrapping_meta": {
    "tag_length": 128,
    "encoding": "base64url"
  }
}
```

## Encrypted Owner Key Vault

The owner key vault stores a JSON bundle of known secret and request keys encrypted under a recovery passphrase.

- Version: `encsend-owner-key-vault-v1`
- Algorithm: `AES-GCM`
- KDF: `PBKDF2-SHA-256`
- Additional authenticated data: `encsend-owner-key-vault-v1`

Encrypted wire format:

```json
{
  "vault_version": "encsend-owner-key-vault-v1",
  "encryption_algorithm": "AES-GCM",
  "encrypted_blob": "<base64url>",
  "encryption_iv": "<base64url>",
  "kdf": {
    "name": "PBKDF2-SHA-256",
    "iterations": 240000,
    "salt": "<base64url>"
  },
  "metadata": {
    "format": "encsend-key-bundle-v1",
    "secret_key_count": 1,
    "request_key_count": 1,
    "exported_at": "<iso8601>"
  }
}
```

The decrypted JSON blob currently contains:

```json
{
  "secret_keys": {
    "<public-id>": "<base64url key>"
  },
  "request_keys": {
    "<public-id>": "<base64url key>"
  },
  "exported_at": "<iso8601>",
  "format": "encsend-key-bundle-v1"
}
```

The runtime API normalizes decrypted vault payloads to:

```json
{
  "secret_keys": {},
  "request_keys": {}
}
```

## Compatibility Rules

- Existing version strings are immutable contracts.
- Field names and cryptographic parameters for an existing version must not change in place.
- Any incompatible change requires a new version string and new deterministic fixtures.
- Deterministic regression vectors under `test-vectors/` are normative compatibility artifacts for this package.
