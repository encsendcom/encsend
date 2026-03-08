# Contributing

Thanks for helping review and improve the EncSend crypto core.

## Scope

This repository is limited to the extracted browser-side cryptographic core,
its deterministic fixtures, and the protocol documentation around those
primitives.

Please keep contributions focused on:

- cryptographic correctness
- deterministic fixture coverage
- protocol clarity
- backward-compatibility and versioning statements
- threat-model precision

Please do not mix in:

- product UI changes
- Laravel controllers or routes
- hosted-service operations
- deployment-specific configuration

## Development

Run the local tests before opening a pull request:

```bash
npm test
```

## Pull Requests

Good pull requests should include:

- a clear explanation of the change
- updated fixtures when formats change
- updated protocol or threat-model documentation when security behavior changes
- explicit compatibility notes when serialized formats are affected

## Security Issues

Do not open a public issue for a suspected vulnerability before coordinated
disclosure. Follow the process in [SECURITY.md](./SECURITY.md).
