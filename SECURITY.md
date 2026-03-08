# Security Policy

## Scope

This policy applies to the code and protocol documentation under `packages/crypto-core`.

Reports about the hosted EncSend service may include issues in adjacent product layers, but this package should be treated as the review boundary for the current Open-Core work.

## Reporting

For a public release of this package, enable a private repository reporting
channel first, for example GitHub private vulnerability reporting.

This package intentionally does not embed a personal, internal, or production
email address. Configure the release-time reporting contact in the public
repository settings or release documentation.

Include:

- affected module or format version
- reproduction steps
- proof-of-concept inputs or payloads when possible
- impact assessment
- any deterministic fixture or test-vector mismatch you observed

Do not disclose a vulnerability publicly before a fix or coordinated mitigation is available.

## What Is Helpful

Useful reports include:

- plaintext recovery without the intended key material
- ciphertext forgery or integrity bypass
- KDF or wrapping parameter downgrade vectors
- cross-version parsing confusion that can break confidentiality or authenticity
- deterministic fixture regressions that indicate silent protocol drift

## Out of Scope

The following are generally out of scope for this package alone:

- denial-of-service reports without a clear security boundary impact
- missing rate limits in hosted services
- operational issues in private infrastructure
- attacks that already require a fully compromised browser environment

## Handling

EncSend will review reports, reproduce the issue, and coordinate a fix. When protocol compatibility is affected, fixes should come with:

- a versioned format change or explicit compatibility statement
- updated deterministic fixtures
- regression coverage for the affected path
