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
| Content encryption | AES-256-GCM (12-byte IV); optional AAD via `additionalData` / `vaultFieldAad` |
| Passphrase KDF | Argon2id (`m=65536` KiB, `t=3`, `p=4`, 32-byte output) via `@noble/hashes`; unlock rejects weakened stored params |
| Domain separation | HKDF-SHA-256 with empty salt and fixed info strings |
| Recovery | BIP39 mnemonic wrapping the vault DEK (`@scure/bip39`) |
| Proof-of-DEK | ECDSA P-256 (`@noble/curves`); private key AES-GCM-wrapped under the vault DEK |

HKDF info strings:

- `heirvault-auth-v1` — auth material derived from the stretched passphrase (used by the product with OPAQUE; this package only performs the HKDF step)
- `heirvault-vault-kek-v1` — vault key-encryption key
- `heirvault-device-wrap-v1` — device wrap domain (exported for product use)
- `heirvault-recovery-auth-v1` — auth material derived from the recovery phrase for recovery sign-in. Unlike the three above it is an HKDF **extract-and-expand** over the phrase with a stored per-account salt, not an expand over an Argon2 stretch. It is fully separate from the recovery *unlock* path, which keeps Argon2id over the same phrase with the wrap's own salt, so neither output yields the other.

### Sync vs. async Argon2

`deriveStretchedKeyBytes` is synchronous and blocks the calling thread for the full Argon2id pass (a few hundred ms to a couple seconds) with no yielding — in a browser this freezes in-flight UI, including CSS animations, since the main thread still owns frame submission. It exists only for tests and non-UI (Node script) contexts.

Every function that touches the vault DEK from browser code (`createVaultCrypto`, `unlockVaultCrypto`, `deriveOpaquePasswordFromPassphrase`, `rewrapDekWithPassphrase`, `deriveVaultKeyArgon2`) already awaits `deriveStretchedKeyBytesAsync` internally, so consumers get this for free. If you add a new call site that needs the stretched key directly, await the `*Async` variant, not the sync one — it's the same algorithm and produces byte-identical output (see `vault-golden.test.ts`), it just doesn't stall the page.

## Live vault format (`VaultCrypto`)

Stored as JSON on the vault row:

```ts
type VaultCrypto = {
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

`parseKeyWrap` validates this shape (rejects malformed JSON and unsupported KDFs).

Callers that encrypt item fields should pass matching `additionalData` on encrypt and decrypt so ciphertext cannot be swapped across vault/item/field context. Helper: `vaultFieldAad({ vaultId, itemId, field, kind })`.

## Proof-of-DEK (`vault-identity`)

Privileged product operations (passphrase replace, kill/panic API keys, key-wrap rotation, handoff publish) require a cryptographic proof that the caller currently holds the vault DEK.

At vault setup:

1. `generateVaultIdentity(dek, { aad: vaultIdentityAad(vaultId) })` creates a P-256 keypair.
2. The compressed public key (`dekPublicKey`) is stored on the vault row (write-once).
3. The private key is AES-GCM-wrapped under the DEK (`encryptedVaultIdentityKey`) with AAD binding to the vault id.

To prove possession:

1. Server issues a single-use challenge (`challengeId`, `nonce`) bound to purpose + vault + session.
2. Client builds the canonical message with `buildDekProofMessage({ purpose, vaultId, challengeId, nonce })`.
3. Client signs with `signDekChallenge(dek, encryptedVaultIdentityKey, message, { aad })`.
4. Server verifies with `verifyDekProof(dekPublicKey, message, signature)` (pure JS; same implementation in the browser and Convex).

Canonical message format:

```text
["heirvault-dek-proof-v2","<purpose>","<vaultId>","<challengeId>","<nonce>"]
```

A JSON array, so no field can smuggle the delimiter and shift the others.
The tag tracks the encoding: v1 was the pipe-joined form.

## Usage

```ts
import {
  createVaultCrypto,
  unlockVaultCrypto,
  encryptVaultSecret,
  decryptVaultSecret,
  generateRecoveryPhrase,
  wrapDekWithRecoveryPhrase,
  unlockDekWithRecovery,
} from '@heirvault/crypto'

const created = await createVaultCrypto('a-strong-passphrase')
const sealed = await encryptVaultSecret('secret note', created.dek)
const unlocked = await unlockVaultCrypto(
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
