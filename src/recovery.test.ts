import { describe, expect, it } from 'vitest'
import { encryptUtf8 } from './aes-gcm'
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveVaultKeyArgon2,
  randomSaltArgon2,
  serializeArgon2Salt,
} from './argon2'
import { bytesToBase64, base64ToBytes } from './encoding'
import {
  generateRecoveryPhrase,
  isValidRecoveryPhrase,
  normalizeRecoveryPhrase,
  unlockDekWithRecovery,
  wrapDekWithRecoveryPhrase,
} from './recovery'
import { exportDekRaw, generateVaultDek, importDekFromRaw } from './vault'

describe('recovery kit', () => {
  it('generates BIP39 phrases with the requested word count', () => {
    expect(generateRecoveryPhrase(12).split(' ')).toHaveLength(12)
    expect(generateRecoveryPhrase(24).split(' ')).toHaveLength(24)
  })

  it('validates generated phrases', () => {
    const phrase = generateRecoveryPhrase(12)
    expect(isValidRecoveryPhrase(phrase)).toBe(true)
    expect(
      isValidRecoveryPhrase('not a real mnemonic phrase at all here')
    ).toBe(false)
  })

  it('wraps and unlocks with a canonical phrase', async () => {
    const dek = await generateVaultDek()
    const phrase = generateRecoveryPhrase(12)
    const wrap = await wrapDekWithRecoveryPhrase(dek, phrase)
    const unlocked = await unlockDekWithRecovery(phrase, wrap)
    expect(bytesToBase64(await exportDekRaw(unlocked))).toBe(
      bytesToBase64(await exportDekRaw(dek))
    )
  })

  it('unlocks when typed input differs only by case or spacing', async () => {
    const dek = await generateVaultDek()
    const phrase = generateRecoveryPhrase(12)
    const wrap = await wrapDekWithRecoveryPhrase(dek, phrase)
    const typed = `  ${phrase.toUpperCase().replace(/ /g, '  ')}  `
    const unlocked = await unlockDekWithRecovery(typed, wrap)
    expect(bytesToBase64(await exportDekRaw(unlocked))).toBe(
      bytesToBase64(await exportDekRaw(dek))
    )
  })

  it('falls back to raw phrase for pre-normalization wraps', async () => {
    const dek = await generateVaultDek()
    const canonical = generateRecoveryPhrase(12)
    const legacyPhrase = `  ${canonical.toUpperCase()}  `
    expect(normalizeRecoveryPhrase(legacyPhrase)).toBe(canonical)
    expect(legacyPhrase).not.toBe(canonical)

    // Simulate historical wrap: KDF used the raw typed string, not normalized.
    const salt = randomSaltArgon2()
    const kek = await deriveVaultKeyArgon2(legacyPhrase, salt)
    const raw = await exportDekRaw(dek)
    const payload = await encryptUtf8(bytesToBase64(raw), kek)
    const wrap = {
      salt: serializeArgon2Salt(salt),
      iterations: ARGON2_ITERATIONS,
      kdf: 'argon2id' as const,
      memory: ARGON2_MEMORY_KIB,
      parallelism: ARGON2_PARALLELISM,
      ciphertext: payload.ciphertext,
      iv: payload.iv,
    }

    const unlocked = await unlockDekWithRecovery(legacyPhrase, wrap)
    expect(bytesToBase64(await exportDekRaw(unlocked))).toBe(
      bytesToBase64(await exportDekRaw(dek))
    )

    // Wrong phrase still fails (no silent accept).
    await expect(
      unlockDekWithRecovery(generateRecoveryPhrase(12), wrap)
    ).rejects.toThrow()
  })

  it('imports the unlocked DEK as a usable AES-GCM key', async () => {
    const dek = await generateVaultDek()
    const phrase = generateRecoveryPhrase(12)
    const wrap = await wrapDekWithRecoveryPhrase(dek, phrase)
    const unlocked = await unlockDekWithRecovery(phrase, wrap)
    const roundTrip = await importDekFromRaw(await exportDekRaw(unlocked))
    expect(bytesToBase64(await exportDekRaw(roundTrip))).toBe(
      bytesToBase64(await exportDekRaw(dek))
    )
  })
})
