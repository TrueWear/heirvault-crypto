import { describe, expect, it } from 'vitest'
import { deriveStretchedKeyBytes, randomSaltArgon2 } from './argon2'
import {
  deriveOpaquePassword,
  deriveVaultKek,
  HKDF_INFO_AUTH,
  HKDF_INFO_VAULT_KEK,
  hkdfExpand,
} from './hkdf'

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// Matches the toArrayBuffer helper duplicated across this package's source
// files: WebCrypto's typings want a real ArrayBuffer, not the
// ArrayBufferLike a Uint8Array carries.
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

describe('hkdf domain separation', () => {
  it('produces different outputs for auth vs vault-kek infos', async () => {
    const salt = randomSaltArgon2()
    const stretched = deriveStretchedKeyBytes('test-password-12', salt)
    const auth = await hkdfExpand(stretched, HKDF_INFO_AUTH)
    const kek = await hkdfExpand(stretched, HKDF_INFO_VAULT_KEK)
    expect(auth).not.toEqual(kek)
    expect(auth.length).toBe(32)
    expect(kek.length).toBe(32)
  }, 90_000)

  it('derives opaque password and vault KEK from the same stretch', async () => {
    const salt = randomSaltArgon2()
    const stretched = deriveStretchedKeyBytes('another-long-pass', salt)
    const opaqueA = await deriveOpaquePassword(stretched)
    const opaqueB = await deriveOpaquePassword(stretched)
    expect(opaqueA).toBe(opaqueB)
    const vaultKek = await deriveVaultKek(stretched)
    expect(vaultKek.algorithm).toMatchObject({ name: 'AES-GCM' })
  }, 90_000)

  /**
   * RFC 5869 Appendix A.1, "Test Case 1" — the published known-answer test
   * for HKDF-SHA-256. `hkdfExpand` always uses an empty salt and a UTF-8
   * `info` string (see its docstring), so RFC Test Case 1's non-empty binary
   * salt and info cannot be driven through that wrapper as-is; this pins the
   * underlying WebCrypto `{name: 'HKDF', hash: 'SHA-256'}` engine
   * `hkdfExpand` calls into directly, using raw bytes for every RFC input.
   * The engine is what could silently drift under a Node/runtime upgrade —
   * `hkdfExpand`'s own tests above only check internal consistency (e.g.
   * "different info strings give different output"), which would stay green
   * through a drift that changed every derived key. Verified against a live
   * run of `crypto.subtle.deriveBits('HKDF', ...)` with these exact inputs
   * before being committed here; do not hand-edit the expected output.
   */
  it('matches the RFC 5869 Appendix A.1 Test Case 1 HKDF-SHA-256 known-answer test vector', async () => {
    const ikm = hexToBytes('0b'.repeat(22))
    const salt = hexToBytes('000102030405060708090a0b0c')
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9')
    const length = 42

    const baseKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(ikm),
      'HKDF',
      false,
      ['deriveBits']
    )
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(info),
      },
      baseKey,
      length * 8
    )

    expect(bytesToHex(new Uint8Array(bits))).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    )
  })
})
