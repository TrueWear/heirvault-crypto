import { describe, expect, it } from 'vitest'
import {
  createVaultCryptoV2,
  unlockVaultCryptoV2,
  rewrapDekWithPassphrase,
  encryptVaultSecret,
  decryptVaultSecret,
  parseVaultCrypto,
  serializeVaultCryptoV2,
  wrapDekWithSecret,
  unwrapDekWithSecret,
} from './vault'
import {
  generateRecoveryPhrase,
  wrapDekWithRecoveryPhrase,
  unlockDekWithRecovery,
  isValidRecoveryPhrase,
} from './recovery'

describe('vault crypto', () => {
  it('creates and unlocks a random DEK wrapped by passphrase', async () => {
    const created = await createVaultCryptoV2('unified-passphrase-ok')
    expect(created.vaultCrypto.version).toBe(2)
    const unlocked = await unlockVaultCryptoV2(
      'unified-passphrase-ok',
      created.vaultCrypto
    )
    const payload = await encryptVaultSecret('hello-v2', unlocked.dek)
    const plain = await decryptVaultSecret(payload, created.dek)
    expect(plain).toBe('hello-v2')
    expect(unlocked.opaquePassword).toBe(created.opaquePassword)
  }, 90_000)

  it('rewraps DEK under a new passphrase without changing content key', async () => {
    const created = await createVaultCryptoV2('original-pass-phrase')
    const payload = await encryptVaultSecret('keep-me', created.dek)
    const rewrapped = await rewrapDekWithPassphrase(
      created.dek,
      'brand-new-pass-phrase'
    )
    const unlocked = await unlockVaultCryptoV2(
      'brand-new-pass-phrase',
      rewrapped.vaultCrypto
    )
    const plain = await decryptVaultSecret(payload, unlocked.dek)
    expect(plain).toBe('keep-me')
  }, 90_000)

  it('recovery phrase wraps and unlocks DEK', async () => {
    const created = await createVaultCryptoV2('pass-for-recovery-12')
    const phrase = generateRecoveryPhrase(12)
    expect(isValidRecoveryPhrase(phrase)).toBe(true)
    const wrap = await wrapDekWithRecoveryPhrase(created.dek, phrase)
    const dek = await unlockDekWithRecovery(phrase, wrap)
    const payload = await encryptVaultSecret('via-recovery', dek)
    const plain = await decryptVaultSecret(payload, created.dek)
    expect(plain).toBe('via-recovery')
  }, 90_000)

  it('wraps DEK with recipient secret including full argon2 params', async () => {
    const created = await createVaultCryptoV2('owner-passphrase-x')
    const wrap = await wrapDekWithSecret(created.dek, 'recipient-secret')
    expect(wrap.kdf).toBe('argon2id')
    expect(wrap.memory).toBeDefined()
    expect(wrap.parallelism).toBeDefined()
    const dek = await unwrapDekWithSecret(wrap, 'recipient-secret')
    const payload = await encryptVaultSecret('for-heir', dek)
    expect(await decryptVaultSecret(payload, created.dek)).toBe('for-heir')
  }, 90_000)

  it('parseVaultCrypto accepts version 2 only', () => {
    const v2 = serializeVaultCryptoV2({
      version: 2,
      accountSalt: 'YQ==',
      kdf: 'argon2id',
      memory: 1,
      iterations: 1,
      parallelism: 1,
      vaultKeyWrap: { ciphertext: 'c', iv: 'i' },
    })
    expect(parseVaultCrypto(v2).version).toBe(2)
    expect(() =>
      parseVaultCrypto(JSON.stringify({ salt: 'x', kdf: 'argon2id' }))
    ).toThrow(/Unsupported vault crypto/)
  })
})
