import { describe, expect, it } from 'vitest'
import { decryptUtf8 } from './aes-gcm'
import { base64ToBytes, bytesToBase64 } from './encoding'
import {
  RECOVERY_SALT_LENGTH,
  deriveRecoveryOpaquePassword,
  generateRecoveryPhrase,
  randomRecoverySalt,
  unlockDekWithRecovery,
  wrapDekWithRecoveryPhrase,
} from './recovery'
import { exportDekRaw, generateVaultDek } from './vault'

/**
 * Fixed phrase (canonical BIP39 all-zero-entropy vector) and salt, with the
 * expected output computed by an independent HKDF-SHA-256 implementation
 * rather than by the code under test.
 *
 * These MUST NOT be regenerated to make a failing test pass. Every enrolled
 * emergency kit depends on this derivation staying byte-identical -- changing
 * it silently locks every existing user out of recovery sign-in, and the
 * failure is indistinguishable from a wrong phrase.
 */
const KAT_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const KAT_SALT = 'AAECAwQFBgcICQoLDA0ODw=='
const KAT_EXPECTED = '5uybV/Ms8Rg/cE2zEAIf30dC8TFBqE1rfUhzvfkL+Xc='

describe('recovery auth derivation', () => {
  it('matches the recorded known-answer vector', async () => {
    await expect(deriveRecoveryOpaquePassword(KAT_PHRASE, KAT_SALT)).resolves.toBe(
      KAT_EXPECTED
    )
  })

  it('normalizes typed input to the canonical phrase', async () => {
    const canonical = await deriveRecoveryOpaquePassword(KAT_PHRASE, KAT_SALT)
    const messyVariants = [
      `  ${KAT_PHRASE}  `,
      KAT_PHRASE.toUpperCase(),
      KAT_PHRASE.replace(/ /g, '  '),
      KAT_PHRASE.replace(/ /g, '\n'),
      KAT_PHRASE.replace(' ', '\t'),
    ]
    for (const variant of messyVariants) {
      await expect(
        deriveRecoveryOpaquePassword(variant, KAT_SALT)
      ).resolves.toBe(canonical)
    }
  })

  it('is deterministic for the same phrase and salt', async () => {
    const phrase = generateRecoveryPhrase(12)
    const salt = randomRecoverySalt()
    const first = await deriveRecoveryOpaquePassword(phrase, salt)
    const second = await deriveRecoveryOpaquePassword(phrase, salt)
    expect(first).toBe(second)
  })

  it('separates by salt, so a rotated credential is a different secret', async () => {
    const phrase = generateRecoveryPhrase(12)
    const a = await deriveRecoveryOpaquePassword(phrase, randomRecoverySalt())
    const b = await deriveRecoveryOpaquePassword(phrase, randomRecoverySalt())
    expect(a).not.toBe(b)
  })

  it('separates by phrase under a shared salt', async () => {
    const salt = randomRecoverySalt()
    const a = await deriveRecoveryOpaquePassword(generateRecoveryPhrase(12), salt)
    const b = await deriveRecoveryOpaquePassword(generateRecoveryPhrase(12), salt)
    expect(a).not.toBe(b)
  })

  it('emits 32-byte secrets and 16-byte salts', async () => {
    const salt = randomRecoverySalt()
    expect(base64ToBytes(salt)).toHaveLength(RECOVERY_SALT_LENGTH)
    const derived = await deriveRecoveryOpaquePassword(
      generateRecoveryPhrase(12),
      salt
    )
    expect(base64ToBytes(derived)).toHaveLength(32)
  })

  it('produces salts with no repeats across many draws', () => {
    const salts = new Set(Array.from({ length: 128 }, () => randomRecoverySalt()))
    expect(salts.size).toBe(128)
  })

  /**
   * '' decodes to zero bytes, and HKDF-Extract treats an empty salt as an
   * all-zero block: an absent or truncated salt column would otherwise yield
   * one globally precomputable secret shared by every account.
   */
  it('rejects any salt that is not exactly RECOVERY_SALT_LENGTH bytes', async () => {
    const phrase = generateRecoveryPhrase(12)
    const wrongLengths = [
      '',
      bytesToBase64(new Uint8Array(0)),
      bytesToBase64(new Uint8Array(RECOVERY_SALT_LENGTH - 1)),
      bytesToBase64(new Uint8Array(RECOVERY_SALT_LENGTH + 1)),
      bytesToBase64(new Uint8Array(32)),
    ]
    for (const salt of wrongLengths) {
      await expect(
        deriveRecoveryOpaquePassword(phrase, salt)
      ).rejects.toThrow(/recovery salt length/i)
    }
  })

  it('accepts a freshly minted salt', async () => {
    await expect(
      deriveRecoveryOpaquePassword(generateRecoveryPhrase(12), randomRecoverySalt())
    ).resolves.toBeTypeOf('string')
  })

  /**
   * The whole point of the split: the value that authenticates must never be
   * the value that decrypts. Leaking one to the server must not yield the
   * other.
   */
  it('is independent of the Argon2id vault-unlock KEK', async () => {
    const phrase = generateRecoveryPhrase(12)
    const dek = await generateVaultDek()
    const wrap = await wrapDekWithRecoveryPhrase(dek, phrase)

    const authSecret = await deriveRecoveryOpaquePassword(
      phrase,
      randomRecoverySalt()
    )

    // The auth secret must not be the DEK itself.
    expect(base64ToBytes(authSecret)).not.toEqual(await exportDekRaw(dek))

    // Nor may it stand in for the KEK: the value handed to the server during
    // authentication must be useless for decrypting the wrap. (The real KEK is
    // deliberately non-extractable, so assert the property that matters.)
    const asKek = await crypto.subtle.importKey(
      'raw',
      base64ToBytes(authSecret) as unknown as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
    await expect(
      decryptUtf8({ ciphertext: wrap.ciphertext, iv: wrap.iv }, asKek)
    ).rejects.toThrow()
  })

  /** Auth derivation must not disturb the wrap format printed kits rely on. */
  it('leaves the existing recovery wrap unlockable', async () => {
    const phrase = generateRecoveryPhrase(12)
    const dek = await generateVaultDek()
    const wrap = await wrapDekWithRecoveryPhrase(dek, phrase)

    await deriveRecoveryOpaquePassword(phrase, randomRecoverySalt())

    const unlocked = await unlockDekWithRecovery(phrase, wrap)
    expect(await exportDekRaw(unlocked)).toEqual(await exportDekRaw(dek))
  })
})
