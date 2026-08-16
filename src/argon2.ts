import { argon2id, argon2idAsync } from '@noble/hashes/argon2'
import { bytesToBase64, base64ToBytes } from './encoding'
import { preparePassphraseForKdf } from './passphrase'

export const ARGON2_MEMORY_KIB = 65536
export const ARGON2_ITERATIONS = 3
export const ARGON2_PARALLELISM = 4
export const ARGON2_KEY_LENGTH = 32
export const ARGON2_SALT_LENGTH = 16

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

/**
 * Stretch passphrase to raw bytes (Argon2id). Used for v2 HKDF root.
 *
 * Synchronous: runs the full memory-hard computation (64 MiB / t=3 / p=4)
 * on the calling thread with no yielding, which blocks the main thread for
 * a few hundred ms to a couple seconds and freezes any in-flight UI
 * (including "compositor-only" CSS animations, since the browser still
 * needs the main thread to keep submitting frames). Reserve this for tests
 * and non-UI (Node script) contexts. Every browser call site must use
 * `deriveStretchedKeyBytesAsync` instead, which yields periodically.
 */
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

/**
 * Async twin of `deriveStretchedKeyBytes` — same algorithm and params,
 * byte-identical output. `@noble/hashes`' async variant checks in between
 * Argon2id passes via `await` on an already-resolved promise, which is a
 * *microtask* yield: it keeps other pending promise chains from starving,
 * but browsers drain the whole microtask queue before painting a frame, so
 * this does NOT free the renderer and will still visibly stall in-flight
 * UI (spinners, CSS animations) for the derivation's full duration. It's
 * the right default for a portable, dependency-free package function, but
 * it is not a fix for main-thread freezing on its own.
 *
 * For a browser call site where the UI must stay responsive, run this (or
 * the `vault.ts` functions that call it) inside a Web Worker and inject
 * that as the `StretchedKeyDeriver` those functions accept — genuinely
 * off-main-thread execution is the only way to keep the renderer live
 * during an intentionally expensive memory-hard KDF.
 */
export async function deriveStretchedKeyBytesAsync(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(
    preparePassphraseForKdf(password)
  )
  return new Uint8Array(
    await argon2idAsync(passwordBytes, salt, {
      t: ARGON2_ITERATIONS,
      m: ARGON2_MEMORY_KIB,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_KEY_LENGTH,
    })
  )
}

/**
 * Injectable strategy for computing the Argon2id-stretched key. The
 * `vault.ts` passphrase functions default to `deriveStretchedKeyBytesAsync`
 * (in-process) but accept an override — pass one backed by a Web Worker
 * from browser code to keep the UI thread responsive during derivation.
 */
export type StretchedKeyDeriver = (
  password: string,
  salt: Uint8Array
) => Promise<Uint8Array>

export async function deriveVaultKeyArgon2(
  password: string,
  salt: Uint8Array,
  deriveStretchedKey: StretchedKeyDeriver = deriveStretchedKeyBytesAsync
): Promise<CryptoKey> {
  const keyBytes = await deriveStretchedKey(password, salt)
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export function randomSaltArgon2(): Uint8Array {
  const salt = new Uint8Array(ARGON2_SALT_LENGTH)
  crypto.getRandomValues(salt)
  return salt
}

export function serializeArgon2Salt(salt: Uint8Array): string {
  return bytesToBase64(salt)
}

export function deserializeArgon2Salt(encoded: string): Uint8Array {
  const salt = base64ToBytes(encoded)
  if (salt.length !== ARGON2_SALT_LENGTH) {
    throw new Error(`Invalid Argon2 salt length: ${salt.length}`)
  }
  return salt
}
