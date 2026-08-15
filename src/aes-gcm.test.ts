import { describe, expect, it } from 'vitest'
import {
  decryptBinary,
  decryptUtf8,
  deviceWrapAad,
  encryptBinary,
  encryptUtf8,
  vaultFieldAad,
} from './aes-gcm'
import { base64ToBytes, bytesToBase64 } from './encoding'

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
}

/** Flip one bit in the last byte — lands inside the 16-byte GCM tag for any
 * payload, since the tag is appended after the ciphertext body. */
function flipLastByte(base64: string): string {
  const bytes = base64ToBytes(base64)
  bytes[bytes.length - 1] = bytes[bytes.length - 1] ^ 0x01
  return bytesToBase64(bytes)
}

/** Flip a bit near the start — lands inside the ciphertext body rather than
 * the tag for any payload longer than 16 bytes. */
function flipFirstByte(base64: string): string {
  const bytes = base64ToBytes(base64)
  bytes[0] = bytes[0] ^ 0x01
  return bytesToBase64(bytes)
}

function truncateGcmTag(ciphertextBase64: string): string {
  const bytes = base64ToBytes(ciphertextBase64)
  // The 16-byte GCM tag is the final 16 bytes; drop it entirely.
  return bytesToBase64(bytes.slice(0, Math.max(0, bytes.length - 16)))
}

describe('aes-gcm', () => {
  it('round-trips utf8 payloads', async () => {
    const key = await aesKey()
    const payload = await encryptUtf8('hello vault', key)
    expect(await decryptUtf8(payload, key)).toBe('hello vault')
  })

  it('round-trips binary payloads', async () => {
    const key = await aesKey()
    const bytes = new Uint8Array([1, 2, 3, 250, 255])
    const sealed = await encryptBinary(bytes, key)
    const opened = await decryptBinary(sealed.ciphertext, sealed.iv, key)
    expect(Array.from(opened)).toEqual(Array.from(bytes))
  })

  it('rejects decryption with the wrong key', async () => {
    const a = await aesKey()
    const b = await aesKey()
    const payload = await encryptUtf8('secret', a)
    await expect(decryptUtf8(payload, b)).rejects.toThrow()
  })

  it('binds utf8 ciphertext to additional authenticated data', async () => {
    const key = await aesKey()
    const aad = vaultFieldAad({
      vaultId: 'vault_1',
      itemId: 'item_1',
      field: 'body',
      kind: 'note',
    })
    const payload = await encryptUtf8('bound', key, { additionalData: aad })
    expect(await decryptUtf8(payload, key, { additionalData: aad })).toBe(
      'bound'
    )
    await expect(decryptUtf8(payload, key)).rejects.toThrow()
    await expect(
      decryptUtf8(payload, key, {
        additionalData: vaultFieldAad({
          vaultId: 'vault_1',
          itemId: 'item_2',
          field: 'body',
          kind: 'note',
        }),
      })
    ).rejects.toThrow()
  })

  it('binds binary ciphertext to additional authenticated data', async () => {
    const key = await aesKey()
    const bytes = new Uint8Array([9, 8, 7])
    const sealed = await encryptBinary(bytes, key, {
      additionalData: 'upload|blob|raw',
    })
    const opened = await decryptBinary(sealed.ciphertext, sealed.iv, key, {
      additionalData: 'upload|blob|raw',
    })
    expect(Array.from(opened)).toEqual(Array.from(bytes))
    await expect(
      decryptBinary(sealed.ciphertext, sealed.iv, key)
    ).rejects.toThrow()
  })

  it('generates a fresh IV on every encryption under the same key', async () => {
    const key = await aesKey()
    const ivs = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const payload = await encryptUtf8('same plaintext', key)
      ivs.add(payload.iv)
    }
    expect(ivs.size).toBe(200)
  })

  it('binds device wraps to their (vaultId, credentialId) via deviceWrapAad', async () => {
    const key = await aesKey()
    const aad = deviceWrapAad({ vaultId: 'vault_1', credentialId: 'cred_1' })
    const payload = await encryptUtf8('wrapped-dek', key, {
      additionalData: aad,
    })
    expect(await decryptUtf8(payload, key, { additionalData: aad })).toBe(
      'wrapped-dek'
    )
    await expect(
      decryptUtf8(payload, key, {
        additionalData: deviceWrapAad({
          vaultId: 'vault_2',
          credentialId: 'cred_1',
        }),
      })
    ).rejects.toThrow()
  })

  it('rejects a tampered ciphertext body (utf8)', async () => {
    // Every other negative test in this file flips the KEY or the AAD, never
    // the ciphertext bytes themselves — so the AEAD's actual job (detecting
    // a modified payload) was never pinned. This is what would catch a
    // silent regression to a non-authenticated mode.
    const key = await aesKey()
    const payload = await encryptUtf8(
      'a payload long enough that the first byte is body, not tag',
      key
    )
    const tampered = { ...payload, ciphertext: flipFirstByte(payload.ciphertext) }
    await expect(decryptUtf8(tampered, key)).rejects.toThrow()
  })

  it('rejects a tampered GCM tag (utf8)', async () => {
    const key = await aesKey()
    const payload = await encryptUtf8('short', key)
    const tampered = { ...payload, ciphertext: flipLastByte(payload.ciphertext) }
    await expect(decryptUtf8(tampered, key)).rejects.toThrow()
  })

  it('rejects a truncated GCM tag (utf8)', async () => {
    const key = await aesKey()
    const payload = await encryptUtf8('short', key)
    const truncated = {
      ...payload,
      ciphertext: truncateGcmTag(payload.ciphertext),
    }
    await expect(decryptUtf8(truncated, key)).rejects.toThrow()
  })

  it('rejects a tampered ciphertext body and a truncated tag (binary)', async () => {
    const key = await aesKey()
    const bytes = new Uint8Array(32).map((_, i) => i)
    const sealed = await encryptBinary(bytes, key)

    const tamperedBody = new Uint8Array(sealed.ciphertext)
    tamperedBody[0] = tamperedBody[0] ^ 0x01
    await expect(
      decryptBinary(tamperedBody, sealed.iv, key)
    ).rejects.toThrow()

    const truncatedTag = sealed.ciphertext.slice(
      0,
      Math.max(0, sealed.ciphertext.length - 16)
    )
    await expect(
      decryptBinary(truncatedTag, sealed.iv, key)
    ).rejects.toThrow()
  })

  it('rejects an IV that is not exactly 12 bytes (utf8 and binary)', async () => {
    // assertIvLength had no test at all before this — every encrypt path
    // generates a correct 12-byte IV, so nothing exercised the decrypt-side
    // guard that rejects a payload claiming a different length.
    const key = await aesKey()
    const payload = await encryptUtf8('iv length matters', key)

    const shortIv = { ...payload, iv: bytesToBase64(new Uint8Array(11)) }
    await expect(decryptUtf8(shortIv, key)).rejects.toThrow(
      'Invalid AES-GCM IV length: 11'
    )

    const longIv = { ...payload, iv: bytesToBase64(new Uint8Array(16)) }
    await expect(decryptUtf8(longIv, key)).rejects.toThrow(
      'Invalid AES-GCM IV length: 16'
    )

    const bytes = new Uint8Array([1, 2, 3])
    const sealed = await encryptBinary(bytes, key)
    await expect(
      decryptBinary(sealed.ciphertext, bytesToBase64(new Uint8Array(11)), key)
    ).rejects.toThrow('Invalid AES-GCM IV length: 11')
    await expect(
      decryptBinary(sealed.ciphertext, bytesToBase64(new Uint8Array(16)), key)
    ).rejects.toThrow('Invalid AES-GCM IV length: 16')
  })

  it('does not collide vaultFieldAad across tuples that would collide under a naive delimiter join', () => {
    // Under a raw `[a, b, c, d].join('|')` these two tuples both produce
    // "vault1|itemA|x|y|z" — the encoding must keep them distinct.
    const a = vaultFieldAad({
      vaultId: 'vault1',
      itemId: 'itemA',
      field: 'x|y',
      kind: 'z',
    })
    const b = vaultFieldAad({
      vaultId: 'vault1',
      itemId: 'itemA',
      field: 'x',
      kind: 'y|z',
    })
    expect(a).not.toBe(b)
  })
})
