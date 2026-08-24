## What changed

Describe the behavior change and why it belongs in AxiomGuard.

## Security boundary

- What input is considered untrusted?
- What does the change explicitly reject or fail closed on?
- What does it *not* protect against?

## Verification

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm pack --dry-run`
- [ ] `npm run scan:self`
- [ ] Positive and negative tests were added for security-sensitive behavior

## Compatibility

Note any Node.js, package-export, framework-adapter, or API compatibility impact.
