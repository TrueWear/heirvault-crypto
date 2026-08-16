import { describe, expect, it } from 'vitest'
import { unlockVaultCrypto, parseVaultCrypto, type VaultCrypto } from './vault'

/**
 * A real VaultCrypto blob, committed once and never regenerated, so this
 * test proves an existing user's stored blob still unwraps under a future
 * code change — not just that encrypt-then-decrypt round-trips against
 * whatever the code currently does. The other vault tests in this repo
 * (vault-v2.test.ts, vault-kdf.test.ts) all create and unlock a blob within
 * the same test run, so a change that broke both `createVaultCrypto` and
 * `unlockVaultCrypto` identically (a real risk: they share
 * deriveStretchedKeyBytes / deriveVaultKek / wrapDekWithKek) could still
 * pass every one of them while bricking every vault created under the old
 * code. This fixture is the one thing in the suite that only exercises the
 * read side, against output the write side is not involved in producing.
 *
 * Generated with passphrase 'heirvault-golden-fixture-do-not-use-for-real-vaults'
 * and the fixed salt 0x00..0x0f via a live run of createVaultCrypto, then
 * independently re-verified by unlocking this exact blob before being
 * committed here. Do not regenerate this fixture to "fix" a failing test —
 * a failure here means something about the KDF/AEAD chain changed output
 * for existing data, which is the exact class of bug this file exists to
 * catch. If the change is intentional (a deliberate crypto version bump),
 * add a new fixture under a new `version`/`cryptoVersion` rather than
 * replacing this one, so both remain covered.
 */
const GOLDEN_PASSPHRASE = 'heirvault-golden-fixture-do-not-use-for-real-vaults'

const GOLDEN_VAULT_CRYPTO_JSON =
  '{"version":2,"accountSalt":"AAECAwQFBgcICQoLDA0ODw==","kdf":"argon2id","memory":65536,"iterations":3,"parallelism":4,"vaultKeyWrap":{"ciphertext":"7v67pL/i+Ad6oYwsiHTe7ETy8v8wkyi5qVtbch7JqQywDKtscIDEkYUpn9kaG5m3O38ay80E4pSyWLrU","iv":"Cq1oKv5JerHS5HEA"}}'

const GOLDEN_EXPECTED_DEK_HEX =
  'c22fa2bc4cb197d3cd9111d0c71ef8adb17c39ebd28d6dbd40ff2227969cb789'

async function dekHex(dek: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', dek)
  return Array.from(new Uint8Array(raw))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

describe('vault crypto golden fixture', () => {
  it('parses a committed VaultCrypto blob from a prior run', () => {
    const parsed: VaultCrypto = parseVaultCrypto(GOLDEN_VAULT_CRYPTO_JSON)
    expect(parsed.version).toBe(2)
    expect(parsed.kdf).toBe('argon2id')
    expect(parsed.memory).toBe(65536)
    expect(parsed.iterations).toBe(3)
    expect(parsed.parallelism).toBe(4)
  })

  it('unwraps the committed blob to the exact DEK it was created with', async () => {
    const vaultCrypto = parseVaultCrypto(GOLDEN_VAULT_CRYPTO_JSON)
    const { dek } = await unlockVaultCrypto(GOLDEN_PASSPHRASE, vaultCrypto)
    expect(await dekHex(dek)).toBe(GOLDEN_EXPECTED_DEK_HEX)
  }, 90_000)

  it('rejects the committed blob under the wrong passphrase', async () => {
    const vaultCrypto = parseVaultCrypto(GOLDEN_VAULT_CRYPTO_JSON)
    await expect(
      unlockVaultCrypto('not-the-golden-passphrase', vaultCrypto)
    ).rejects.toThrow()
  }, 90_000)
})
