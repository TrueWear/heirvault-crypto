import { describe, expect, it } from 'vitest'
import { deriveStretchedKeyBytes, randomSaltArgon2 } from './argon2'
import {
  PASSWORD_HARD_MAX_BYTES,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  getPasswordPolicyError,
  isPasswordPolicySatisfied,
  normalizePassword,
  preparePasswordForKdf,
} from './password'

describe('password policy', () => {
  it('accepts printable symbols and spaces within length bounds', () => {
    expect(getPasswordPolicyError('correct horse!')).toBeNull()
    expect(isPasswordPolicySatisfied('p@ss phrase!!')).toBe(true)
  })

  it('accepts exactly the minimum and rejects one below it', () => {
    // The boundary had no test at all, which is how the constant could move
    // without anything noticing. It is the floor on the Argon2id input, so it
    // is the one number here worth pinning in both directions.
    expect(
      getPasswordPolicyError('a'.repeat(PASSWORD_MIN_LENGTH))
    ).toBeNull()
    expect(
      getPasswordPolicyError('a'.repeat(PASSWORD_MIN_LENGTH - 1))
    ).toBe('too_short')
  })

  it('rejects short, long, and control-character passwords', () => {
    expect(getPasswordPolicyError('short')).toBe('too_short')
    expect(
      getPasswordPolicyError('a'.repeat(PASSWORD_MAX_LENGTH + 1))
    ).toBe('too_long')
    expect(getPasswordPolicyError(`good-enough\u0000x`)).toBe('control_chars')
    expect(getPasswordPolicyError(`tab\there-is-bad`)).toBe('control_chars')
  })

  it('normalizes to NFC', () => {
    const nfc = 'café'
    const nfd = 'cafe\u0301'
    expect(nfc).not.toBe(nfd)
    expect(normalizePassword(nfd)).toBe(nfc)
  })

  it('derives the same Argon2 stretch for NFC and NFD input', () => {
    const salt = randomSaltArgon2()
    const nfc = 'é'.repeat(PASSWORD_MIN_LENGTH)
    const nfd = 'e\u0301'.repeat(PASSWORD_MIN_LENGTH)
    expect(nfc).not.toBe(nfd)
    expect(
      Buffer.from(deriveStretchedKeyBytes(nfc, salt)).toString('hex')
    ).toBe(Buffer.from(deriveStretchedKeyBytes(nfd, salt)).toString('hex'))
  }, 90_000)

  it('rejects oversized UTF-8 at the KDF boundary', () => {
    const oversized = '😀'.repeat(PASSWORD_HARD_MAX_BYTES)
    expect(() => preparePasswordForKdf(oversized)).toThrow(
      /Password is too long/
    )
  })
})
