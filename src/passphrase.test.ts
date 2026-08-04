import { describe, expect, it } from 'vitest'
import { deriveStretchedKeyBytes, randomSaltArgon2 } from './argon2'
import {
  PASSPHRASE_HARD_MAX_BYTES,
  PASSPHRASE_MAX_LENGTH,
  PASSPHRASE_MIN_LENGTH,
  getPassphrasePolicyError,
  isPassphrasePolicySatisfied,
  normalizePassphrase,
  preparePassphraseForKdf,
} from './passphrase'

describe('passphrase policy', () => {
  it('accepts printable symbols and spaces within length bounds', () => {
    expect(getPassphrasePolicyError('correct horse!')).toBeNull()
    expect(isPassphrasePolicySatisfied('p@ss phrase!!')).toBe(true)
  })

  it('rejects short, long, and control-character passphrases', () => {
    expect(getPassphrasePolicyError('short')).toBe('too_short')
    expect(
      getPassphrasePolicyError('a'.repeat(PASSPHRASE_MAX_LENGTH + 1))
    ).toBe('too_long')
    expect(getPassphrasePolicyError(`good-enough\u0000x`)).toBe('control_chars')
    expect(getPassphrasePolicyError(`tab\there-is-bad`)).toBe('control_chars')
  })

  it('normalizes to NFC', () => {
    const nfc = 'café'
    const nfd = 'cafe\u0301'
    expect(nfc).not.toBe(nfd)
    expect(normalizePassphrase(nfd)).toBe(nfc)
  })

  it('derives the same Argon2 stretch for NFC and NFD input', () => {
    const salt = randomSaltArgon2()
    const nfc = 'é'.repeat(PASSPHRASE_MIN_LENGTH)
    const nfd = 'e\u0301'.repeat(PASSPHRASE_MIN_LENGTH)
    expect(nfc).not.toBe(nfd)
    expect(
      Buffer.from(deriveStretchedKeyBytes(nfc, salt)).toString('hex')
    ).toBe(Buffer.from(deriveStretchedKeyBytes(nfd, salt)).toString('hex'))
  }, 90_000)

  it('rejects oversized UTF-8 at the KDF boundary', () => {
    const oversized = '😀'.repeat(PASSPHRASE_HARD_MAX_BYTES)
    expect(() => preparePassphraseForKdf(oversized)).toThrow(
      /Passphrase is too long/
    )
  })
})
