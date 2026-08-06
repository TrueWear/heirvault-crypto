import { describe, expect, it } from 'vitest'
import {
  assertSupportedArgon2Params,
  createVaultCryptoV2,
  unlockVaultCryptoV2,
  rewrapDekWithPassphrase,
  encryptVaultSecret,
  decryptVaultSecret,
  parseKeyWrap,
  parseVaultCrypto,
  serializeKeyWrap,
  serializeVaultCryptoV2,
  wrapDekWithSecret,
  unwrapDekWithSecret,
} from './vault'
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from './argon2'
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

  it('rejects weakened Argon2 params on unlock', async () => {
    const created = await createVaultCryptoV2('param-check-passphrase')
    await expect(
      unlockVaultCryptoV2('param-check-passphrase', {
        ...created.vaultCrypto,
        memory: 1024,
      })
    ).rejects.toThrow(/Unsupported Argon2 memory/)
    expect(() =>
      assertSupportedArgon2Params({
        kdf: 'argon2id',
        memory: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
      })
    ).not.toThrow()
  }, 90_000)

  it('validates KeyWrap JSON shape', async () => {
    const created = await createVaultCryptoV2('wrap-parse-passphrase')
    const wrap = await wrapDekWithSecret(created.dek, 'recipient-secret')
    const ok = parseKeyWrap(serializeKeyWrap(wrap))
    expect(ok.kdf).toBe('argon2id')
    expect(ok.ciphertext).toBe(wrap.ciphertext)
    expect(() => parseKeyWrap('{')).toThrow(/Invalid key wrap JSON/)
    expect(() => parseKeyWrap(JSON.stringify({ kdf: 'argon2id' }))).toThrow(
      /Invalid key wrap fields/
    )
    expect(() =>
      parseKeyWrap(
        JSON.stringify({
          ...wrap,
          kdf: 'pbkdf2',
        })
      )
    ).toThrow(/Invalid key wrap fields/)
  }, 90_000)
})
