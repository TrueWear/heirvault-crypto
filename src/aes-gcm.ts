import { base64ToBytes, bytesToBase64 } from './encoding'

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

const IV_LENGTH = 12

export type EncryptedPayload = {
  ciphertext: string
  iv: string
}

export async function encryptUtf8(
  plaintext: string,
  key: CryptoKey
): Promise<EncryptedPayload> {
  const iv = new Uint8Array(IV_LENGTH)
  crypto.getRandomValues(iv)
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    new TextEncoder().encode(plaintext)
  )
  return {
    ciphertext: bytesToBase64(new Uint8Array(cipherBuffer)),
    iv: bytesToBase64(iv),
  }
}

export async function decryptUtf8(
  payload: EncryptedPayload,
  key: CryptoKey
): Promise<string> {
  const iv = base64ToBytes(payload.iv)
  const ciphertext = base64ToBytes(payload.ciphertext)
  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext)
  )
  return new TextDecoder().decode(plainBuffer)
}

/** Encrypt binary for storage upload; ciphertext is raw bytes, iv is base64. */
export async function encryptBinary(
  plaintext: Uint8Array,
  key: CryptoKey
): Promise<{ ciphertext: Uint8Array; iv: string }> {
  const iv = new Uint8Array(IV_LENGTH)
  crypto.getRandomValues(iv)
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(plaintext)
  )
  return {
    ciphertext: new Uint8Array(cipherBuffer),
    iv: bytesToBase64(iv),
  }
}

export async function decryptBinary(
  ciphertext: Uint8Array,
  ivBase64: string,
  key: CryptoKey
): Promise<Uint8Array> {
  const iv = base64ToBytes(ivBase64)
  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext)
  )
  return new Uint8Array(plainBuffer)
}
