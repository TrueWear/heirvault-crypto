import { argon2id } from '@noble/hashes/argon2'
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

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function fillBytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value)
}

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

  it('derives different keys for different passwords', () => {
    const salt = randomSaltArgon2()
    const a = deriveStretchedKeyBytes('alpha-password', salt)
    const b = deriveStretchedKeyBytes('beta-password', salt)
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

  /**
   * RFC 9106 Appendix A.1, "Test Vectors for Argon2id" — the published
   * known-answer test for the primitive @noble/hashes/argon2's `argon2id`
   * implements. This does NOT exercise deriveStretchedKeyBytes (which fixes
   * HeirVault's own m/t/p and has no secret/associated-data inputs); it pins
   * the underlying dependency itself. If @noble/hashes ever changes its
   * Argon2id output for a given input — a version bump, a bug fix, a
   * rewrite — this fails immediately in CI. Without it, the same drift would
   * silently change every future `deriveStretchedKeyBytes` output while
   * every other test in this file (which only checks internal consistency,
   * e.g. "same input twice gives the same output") stayed green, and
   * `assertSupportedArgon2Params` would then reject every existing user's
   * vault as "unsupported" — bricking them, not just failing to encrypt new
   * data. Verified against a live run of `argon2id()` with these exact
   * inputs before being committed here; do not hand-edit the expected tag.
   */
  it('matches the RFC 9106 Appendix A.1 Argon2id known-answer test vector', () => {
    const password = fillBytes(32, 0x01)
    const salt = fillBytes(16, 0x02)
    const secret = fillBytes(8, 0x03)
    const associatedData = fillBytes(12, 0x04)

    const tag = argon2id(password, salt, {
      t: 3,
      m: 32, // KiB — the RFC vector's own memory cost, NOT ARGON2_MEMORY_KIB
      p: 4,
      key: secret,
      personalization: associatedData,
      dkLen: 32,
    })

    expect(hex(tag)).toBe(
      '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
    )
  })
})
