import { argon2id } from '@noble/hashes/argon2'
import { bytesToBase64, base64ToBytes } from './encoding'
import { preparePassphraseForKdf } from './passphrase'

export const ARGON2_MEMORY_KIB = 65536
export const ARGON2_ITERATIONS = 3
export const ARGON2_PARALLELISM = 4
export const ARGON2_KEY_LENGTH = 32

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

/** Stretch passphrase to raw bytes (Argon2id). Used for v2 HKDF root. */
export function deriveStretchedKeyBytes(
  password: string,
  salt: Uint8Array
): Uint8Array {
  const passwordBytes = new TextEncoder().encode(
    preparePassphraseForKdf(password)
  )
  return new Uint8Array(
    argon2id(passwordBytes, salt, {
      t: ARGON2_ITERATIONS,
      m: ARGON2_MEMORY_KIB,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_KEY_LENGTH,
    })
  )
}

export async function deriveVaultKeyArgon2(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const keyBytes = deriveStretchedKeyBytes(password, salt)
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export function randomSaltArgon2(): Uint8Array {
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  return salt
}

export function serializeArgon2Salt(salt: Uint8Array): string {
  return bytesToBase64(salt)
}

export function deserializeArgon2Salt(encoded: string): Uint8Array {
  return base64ToBytes(encoded)
}
