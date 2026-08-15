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

export type AesGcmOptions = {
  /**
   * Additional authenticated data (context binding). Must match on decrypt.
   * Bind vaultId|itemId|field|kind (or similar) so ciphertext cannot be swapped
   * across rows/fields.
   */
  additionalData?: string | Uint8Array
}

function encodeAad(
  additionalData: string | Uint8Array | undefined
): ArrayBuffer | undefined {
  if (additionalData === undefined) return undefined
  if (typeof additionalData === 'string') {
    return toArrayBuffer(new TextEncoder().encode(additionalData))
  }
  return toArrayBuffer(additionalData)
}

/** All payloads are produced with a 96-bit IV; reject anything else early. */
function assertIvLength(iv: Uint8Array): void {
  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid AES-GCM IV length: ${iv.length}`)
  }
}

export async function encryptUtf8(
  plaintext: string,
  key: CryptoKey,
  options?: AesGcmOptions
): Promise<EncryptedPayload> {
  const iv = new Uint8Array(IV_LENGTH)
  crypto.getRandomValues(iv)
  const additionalData = encodeAad(options?.additionalData)
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      ...(additionalData ? { additionalData } : {}),
    },
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
  key: CryptoKey,
  options?: AesGcmOptions
): Promise<string> {
  const iv = base64ToBytes(payload.iv)
  assertIvLength(iv)
  const ciphertext = base64ToBytes(payload.ciphertext)
  const additionalData = encodeAad(options?.additionalData)
  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      ...(additionalData ? { additionalData } : {}),
    },
    key,
    toArrayBuffer(ciphertext)
  )
  return new TextDecoder().decode(plainBuffer)
}

/** Encrypt binary for storage upload; ciphertext is raw bytes, iv is base64. */
export async function encryptBinary(
  plaintext: Uint8Array,
  key: CryptoKey,
  options?: AesGcmOptions
): Promise<{ ciphertext: Uint8Array; iv: string }> {
  const iv = new Uint8Array(IV_LENGTH)
  crypto.getRandomValues(iv)
  const additionalData = encodeAad(options?.additionalData)
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      ...(additionalData ? { additionalData } : {}),
    },
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
  key: CryptoKey,
  options?: AesGcmOptions
): Promise<Uint8Array> {
  const iv = base64ToBytes(ivBase64)
  assertIvLength(iv)
  const additionalData = encodeAad(options?.additionalData)
  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      ...(additionalData ? { additionalData } : {}),
    },
    key,
    toArrayBuffer(ciphertext)
  )
  return new Uint8Array(plainBuffer)
}

/**
 * Canonical AAD string for vault/handoff field binding.
 *
 * Encoded as JSON rather than delimiter-joined so distinct (vaultId, itemId,
 * field, kind) tuples can never collide onto the same AAD string (e.g. a
 * naive `join('|')` lets field="x|y" collide with field="x", kind="y").
 */
export function vaultFieldAad(parts: {
  vaultId: string
  itemId: string
  field: string
  kind?: string
}): string {
  return JSON.stringify([
    parts.vaultId,
    parts.itemId,
    parts.field,
    parts.kind ?? '',
  ])
}
