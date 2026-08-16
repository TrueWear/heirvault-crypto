import { bytesToBase64, base64ToBytes } from './encoding'

export const HKDF_INFO_AUTH = 'heirvault-auth-v1'
export const HKDF_INFO_VAULT_KEK = 'heirvault-vault-kek-v1'
export const HKDF_INFO_DEVICE = 'heirvault-device-wrap-v1'
export const HKDF_INFO_RECOVERY_AUTH = 'heirvault-recovery-auth-v1'

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

/**
 * HKDF-SHA-256 expand from an already-extracted IKM (stretched passphrase).
 * Salt is empty; domain separation uses the info string.
 */
export async function hkdfExpand(
  ikm: Uint8Array,
  info: string,
  length = 32
): Promise<Uint8Array> {
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
      salt: new ArrayBuffer(0),
      info: toArrayBuffer(new TextEncoder().encode(info)),
    },
    baseKey,
    length * 8
  )
  return new Uint8Array(bits)
}

/**
 * Full HKDF-SHA-256 (extract + expand) with a caller-supplied salt.
 *
 * Use this when the IKM is a high-entropy secret that has NOT been through a
 * memory-hard KDF -- the salt does the domain-separating work that
 * `hkdfExpand`'s empty salt leaves to the info string alone.
 */
export async function hkdfExtractExpand(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length = 32
): Promise<Uint8Array> {
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
      info: toArrayBuffer(new TextEncoder().encode(info)),
    },
    baseKey,
    length * 8
  )
  return new Uint8Array(bits)
}

export async function deriveOpaquePassword(
  stretchedKey: Uint8Array
): Promise<string> {
  const authBytes = await hkdfExpand(stretchedKey, HKDF_INFO_AUTH)
  return bytesToBase64(authBytes)
}

export async function deriveVaultKek(
  stretchedKey: Uint8Array
): Promise<CryptoKey> {
  const kekBytes = await hkdfExpand(stretchedKey, HKDF_INFO_VAULT_KEK)
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(kekBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export function serializeKeyBytes(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
}

export function deserializeKeyBytes(encoded: string): Uint8Array {
  return base64ToBytes(encoded)
}
