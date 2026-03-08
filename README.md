# EncSend Crypto Core

This package contains the browser-side cryptographic core extracted from EncSend.

Current scope:

- AES-GCM payload encryption and decryption
- Link-key wrapping
- Password-based key wrapping
- Owner recovery profile encryption and key wrapping
- Encrypted owner key vault backup format
- Base64url helpers used by the crypto formats

Out of scope:

- DOM handling
- Blade / Laravel UI integration
- Public link flows
- OTP and password challenge flows
- Network requests and product-specific orchestration

The package is currently kept private inside the main EncSend repository while the
Open-Core split is being stabilized. Public release should only happen together
with protocol documentation, test vectors, and a security disclosure policy.

Documentation prepared for that release now lives in:

- [Protocol](./PROTOCOL.md)
- [Threat Model](./THREAT_MODEL.md)
- [Security Policy](./SECURITY.md)
- [API Stability](./API_STABILITY.md)
- [Module Boundaries](./MODULE_BOUNDARIES.md)
- [Contributing](./CONTRIBUTING.md)
- [Changelog](./CHANGELOG.md)

## Testing

Deterministic regression vectors live under `test-vectors/` and can be validated with:

```bash
npm test
```

These fixtures freeze randomness and timestamps so that payload formats, wrapping
metadata, and recovery artifacts cannot drift silently during refactors.

All bundled test vectors are synthetic. They do not contain production secrets,
real user data, private domains, or operational credentials.
