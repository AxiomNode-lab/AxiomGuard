# Contributing

Contributions are welcome when they keep the package small, auditable, and security-focused.

## Before opening a PR

1. Add or update tests for behavior changes.
2. Run `npm run typecheck` and `npm test`.
3. Avoid new runtime dependencies unless there is a clear security or maintenance benefit.
4. Do not add payload collections, offensive automation, or claims that are not covered by tests.
5. Document security assumptions and failure modes for new security-sensitive helpers.

For vulnerability reports, follow `SECURITY.md` instead of opening a public issue.
