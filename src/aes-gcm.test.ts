import { describe, expect, it } from 'vitest'
import {
  decryptBinary,
  decryptUtf8,
  encryptBinary,
  encryptUtf8,
  vaultFieldAad,
} from './aes-gcm'

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
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
})
