# Contributing

Thanks for helping improve HeirVault's live vault crypto.

## Before you start

- Keep changes focused on this library. Product handoff, claim, session, and server code belong in the private HeirVault app, not here.
- Do not weaken password policy or Argon2 parameters without a clear security rationale and tests.
- Match existing style: TypeScript strict, Vitest, no unnecessary deps.

## Setup

```bash
pnpm install
pnpm type-check
pnpm test
pnpm build
```

## Pull requests

1. Add or update tests for crypto behavior changes.
2. Keep README vault-format docs in sync if shapes or parameters change.
3. Do not add secrets, env examples with real keys, or assisted-escrow documentation.

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
