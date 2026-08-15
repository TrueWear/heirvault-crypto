import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './encoding'
import {
  ARGON2_ITERATIONS,
  ARGON2_KEY_LENGTH,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveStretchedKeyBytes,
  deserializeArgon2Salt,
  randomSaltArgon2,
  serializeArgon2Salt,
} from './argon2'

describe('argon2', () => {
  it('exposes the HeirVault Argon2id parameters', () => {
    expect(ARGON2_MEMORY_KIB).toBe(65536)
    expect(ARGON2_ITERATIONS).toBe(3)
    expect(ARGON2_PARALLELISM).toBe(4)
    expect(ARGON2_KEY_LENGTH).toBe(32)
  })

  it('round-trips salt serialization', () => {
    const salt = randomSaltArgon2()
    expect(salt.byteLength).toBe(16)
    expect(
      Array.from(deserializeArgon2Salt(serializeArgon2Salt(salt)))
    ).toEqual(Array.from(salt))
  })

  it('derives a stable 32-byte stretched key for the same inputs', () => {
    const salt = randomSaltArgon2()
    const a = deriveStretchedKeyBytes('correct-horse-battery-staple', salt)
    const b = deriveStretchedKeyBytes('correct-horse-battery-staple', salt)
    expect(a.byteLength).toBe(32)
    expect(Array.from(a)).toEqual(Array.from(b))
  }, 90_000)

  it('derives different keys for different passphrases', () => {
    const salt = randomSaltArgon2()
    const a = deriveStretchedKeyBytes('alpha-passphrase', salt)
    const b = deriveStretchedKeyBytes('beta-passphrase', salt)
    expect(Array.from(a)).not.toEqual(Array.from(b))
  }, 90_000)

  it('rejects a deserialized salt of the wrong length', () => {
    expect(() => deserializeArgon2Salt(bytesToBase64(new Uint8Array(8)))).toThrow(
      'Invalid Argon2 salt length'
    )
    expect(() =>
      deserializeArgon2Salt(bytesToBase64(new Uint8Array(32)))
    ).toThrow('Invalid Argon2 salt length')
  })
})
