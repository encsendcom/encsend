# Publishing Checklist

Use this checklist before publishing `packages/crypto-core` to GitHub.

## Repository Setup

- create a new clean public repository instead of pushing the private product history
- copy only the public-core files and selected documentation
- enable private vulnerability reporting before first publication
- decide whether the repository is documentation-only or should also be installable as a package

## Legal and Policy

- confirm the MIT license in [LICENSE](./LICENSE) and [package.json](./package.json) matches the intended public release
- confirm whether the `EncSend` name may be used publicly or whether a trademark note is needed
- review [SECURITY.md](./SECURITY.md) and add the final disclosure channel in repository settings or release notes

## Content Audit

- verify there are no real secrets, API keys, access tokens, or infrastructure credentials
- verify there are no internal domains, internal hostnames, or deployment URLs
- verify there are no hard-coded production email addresses
- verify fixtures remain synthetic and do not contain real user data
- verify there are no comments such as `TODO live token`, `FIXME prod`, or similar release-risk markers

## Technical Review

- run `npm test`
- validate the deterministic fixtures still match current outputs
- confirm `src/index.js` exports only intended public modules
- confirm `files` in [package.json](./package.json) matches the intended public package contents
- re-read [PROTOCOL.md](./PROTOCOL.md), [THREAT_MODEL.md](./THREAT_MODEL.md), and [API_STABILITY.md](./API_STABILITY.md) for wording that overclaims product-wide review

## Recommended Extras

- add a short `SECURITY_CONTACT` section in the public repository README or security settings
- run a final secret-scan against the public repository contents before first push
