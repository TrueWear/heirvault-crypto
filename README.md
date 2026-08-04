# @heirvault/crypto

Client-side live vault cryptography used by [HeirVault](https://heirvault.io).

This package implements the browser-side encryption for the **live vault**: AES-256-GCM, Argon2id, HKDF-SHA-256, and BIP39 recovery wraps. It is the auditable crypto layer, not the full HeirVault product (same idea as Proton shipping gopenpgp separately from the full clients).

## Trust boundary

Your live vault encrypts in the browser before upload. That means HeirVault stores ciphertext and cannot decrypt your live vault.

Assisted delivery is a separate HeirVault product feature: it stores a protected handoff key and is not end-to-end to the beneficiary alone. That path is **not** implemented in this library.

This library has **not** been third-party audited yet. Do not treat open source as a substitute for an audit.

## Install

```bash
pnpm add @heirvault/crypto
```

Requires a Web Crypto environment (`crypto.subtle` and `crypto.getRandomValues`), including modern browsers and Node 20+.

## Algorithms

| Piece | Choice |
| --- | --- |
| Content encryption | AES-256-GCM (12-byte IV) |
| Passphrase KDF | Argon2id (`m=65536` KiB, `t=3`, `p=4`, 32-byte output) via `@noble/hashes` |
| Domain separation | HKDF-SHA-256 with empty salt and fixed info strings |
| Recovery | BIP39 mnemonic wrapping the vault DEK (`@scure/bip39`) |

HKDF info strings:

- `heirvault-auth-v1` — auth material derived from the stretched passphrase (used by the product with OPAQUE; this package only performs the HKDF step)
- `heirvault-vault-kek-v1` — vault key-encryption key
- `heirvault-device-wrap-v1` — device wrap domain (exported for product use)

## Live vault format (`VaultCryptoV2`)

Stored as JSON on the vault row:

```ts
type VaultCryptoV2 = {
  version: 2
  accountSalt: string // base64 Argon2 salt
  kdf: 'argon2id'
  memory: number
  iterations: number
  parallelism: number
  vaultKeyWrap: {
    ciphertext: string // base64 AES-GCM of base64 DEK
    iv: string // base64
  }
}
```

`KeyWrap` is used for recovery (and other product wraps that stay outside this package):

```ts
type KeyWrap = {
  salt: string
  iterations: number
  kdf: 'argon2id'
  memory?: number
  parallelism?: number
  ciphertext: string
  iv: string
}
```

## Usage

```ts
import {
  createVaultCryptoV2,
  unlockVaultCryptoV2,
  encryptVaultSecret,
  decryptVaultSecret,
  generateRecoveryPhrase,
  wrapDekWithRecoveryPhrase,
  unlockDekWithRecovery,
} from '@heirvault/crypto'

const created = await createVaultCryptoV2('a-strong-passphrase')
const sealed = await encryptVaultSecret('secret note', created.dek)
const unlocked = await unlockVaultCryptoV2(
  'a-strong-passphrase',
  created.vaultCrypto
)
const plain = await decryptVaultSecret(sealed, unlocked.dek)

const phrase = generateRecoveryPhrase()
const recoveryWrap = await wrapDekWithRecoveryPhrase(created.dek, phrase)
const fromRecovery = await unlockDekWithRecovery(phrase, recoveryWrap)
```

Subpath imports are available: `@heirvault/crypto/vault`, `@heirvault/crypto/aes-gcm`, and so on.

## Non-goals

This repository does **not** include:

- Assisted handoff / escrow sealing or claim protocol
- OPAQUE client/server protocol (only HKDF-derived auth material helper)
- Session unlock, IndexedDB device wraps, or WebAuthn PRF ceremonies
- HeirVault server code or environment secrets

## Security

Report vulnerabilities to [security@heirvault.io](mailto:security@heirvault.io). See [SECURITY.md](./SECURITY.md).

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Development

```bash
pnpm install
pnpm type-check
pnpm test
pnpm build
```
