import { encryptUtf8, decryptUtf8, type EncryptedPayload } from './aes-gcm'
import { bytesToBase64, base64ToBytes } from './encoding'
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveStretchedKeyBytesAsync,
  deriveVaultKeyArgon2,
  randomSaltArgon2,
  serializeArgon2Salt,
  deserializeArgon2Salt,
  type StretchedKeyDeriver,
} from './argon2'
import { deriveOpaquePassword, deriveVaultKek } from './hkdf'

export type KdfType = 'argon2id'

/** Wrap of a random DEK under a KEK (passphrase, recovery, recipient, or device). */
export type KeyWrap = {
  salt: string
  iterations: number
  kdf: KdfType
  memory?: number
  parallelism?: number
  ciphertext: string
  iv: string
}

/** Vault crypto blob stored as JSON on the vault row. */
export type VaultCrypto = {
  version: 2
  accountSalt: string
  kdf: 'argon2id'
  memory: number
  iterations: number
  parallelism: number
  vaultKeyWrap: {
    ciphertext: string
    iv: string
  }
}

export type VaultDek = CryptoKey

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer
}

export async function generateVaultDek(): Promise<VaultDek> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
}

export async function exportDekRaw(dek: VaultDek): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', dek)
  return new Uint8Array(raw)
}

export async function importDekFromRaw(
  raw: Uint8Array,
  extractable = true
): Promise<VaultDek> {
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(raw),
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  )
}

export async function wrapDekWithKek(
  dek: VaultDek,
  kek: CryptoKey,
  options?: { additionalData?: string }
): Promise<EncryptedPayload> {
  const raw = await exportDekRaw(dek)
  return encryptUtf8(bytesToBase64(raw), kek, options)
}

export async function unwrapDekWithKek(
  wrap: EncryptedPayload,
  kek: CryptoKey,
  options?: { additionalData?: string }
): Promise<VaultDek> {
  const rawB64 = await decryptUtf8(wrap, kek, options)
  return importDekFromRaw(base64ToBytes(rawB64))
}

export type PassphraseDerivedMaterial = {
  accountSalt: Uint8Array
  stretchedKey: Uint8Array
  vaultKek: CryptoKey
  opaquePassword: string
  vaultCrypto: VaultCrypto
  dek: VaultDek
}

/** Create a new vault: random DEK + passphrase wrap + OPAQUE password material. */
export async function createVaultCrypto(
  passphrase: string,
  options?: {
    accountSaltB64?: string
    deriveStretchedKey?: StretchedKeyDeriver
  }
): Promise<PassphraseDerivedMaterial> {
  const deriveStretchedKey =
    options?.deriveStretchedKey ?? deriveStretchedKeyBytesAsync
  const accountSalt = options?.accountSaltB64
    ? deserializeArgon2Salt(options.accountSaltB64)
    : randomSaltArgon2()
  const stretchedKey = await deriveStretchedKey(passphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const dek = await generateVaultDek()
  const wrap = await wrapDekWithKek(dek, vaultKek)
  const vaultCrypto: VaultCrypto = {
    version: 2,
    accountSalt: serializeArgon2Salt(accountSalt),
    kdf: 'argon2id',
    memory: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
    vaultKeyWrap: {
      ciphertext: wrap.ciphertext,
      iv: wrap.iv,
    },
  }
  return {
    accountSalt,
    stretchedKey,
    vaultKek,
    opaquePassword,
    vaultCrypto,
    dek,
  }
}

/**
 * Reject unknown or weakened Argon2 suites.
 *
 * Read this precisely: it rejects a stored parameter that disagrees with the
 * supported suite, but a wrap that simply omits `memory`/`iterations`/
 * `parallelism` passes. That is safe only because derivation never consults
 * these fields -- `deriveVaultKeyArgon2` always uses the ARGON2_* module
 * constants -- so an attacker cannot weaken a derivation by editing or
 * dropping them. They are advisory, recorded so a future migration can tell
 * which suite produced a wrap.
 *
 * If derivation is ever changed to honor stored params, this check must
 * become mandatory-field validation first, or omitting a field turns into a
 * downgrade vector.
 */
export function assertSupportedArgon2Params(cryptoBlob: {
  kdf: string
  memory?: number
  iterations?: number
  parallelism?: number
}): void {
  if (cryptoBlob.kdf !== 'argon2id') {
    throw new Error('Unsupported vault crypto KDF')
  }
  if (
    cryptoBlob.memory !== undefined &&
    cryptoBlob.memory !== ARGON2_MEMORY_KIB
  ) {
    throw new Error('Unsupported Argon2 memory parameter')
  }
  if (
    cryptoBlob.iterations !== undefined &&
    cryptoBlob.iterations !== ARGON2_ITERATIONS
  ) {
    throw new Error('Unsupported Argon2 iterations parameter')
  }
  if (
    cryptoBlob.parallelism !== undefined &&
    cryptoBlob.parallelism !== ARGON2_PARALLELISM
  ) {
    throw new Error('Unsupported Argon2 parallelism parameter')
  }
}

/** Unlock vault DEK from passphrase + stored crypto blob. */
export async function unlockVaultCrypto(
  passphrase: string,
  cryptoBlob: VaultCrypto,
  options?: { deriveStretchedKey?: StretchedKeyDeriver }
): Promise<{ dek: VaultDek; opaquePassword: string; vaultKek: CryptoKey }> {
  const deriveStretchedKey =
    options?.deriveStretchedKey ?? deriveStretchedKeyBytesAsync
  assertSupportedArgon2Params(cryptoBlob)
  const accountSalt = deserializeArgon2Salt(cryptoBlob.accountSalt)
  const stretchedKey = await deriveStretchedKey(passphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const dek = await unwrapDekWithKek(cryptoBlob.vaultKeyWrap, vaultKek)
  return { dek, opaquePassword, vaultKek }
}

/** Derive OPAQUE password only (login without unwrap). */
export async function deriveOpaquePasswordFromPassphrase(
  passphrase: string,
  accountSaltB64: string,
  options?: { deriveStretchedKey?: StretchedKeyDeriver }
): Promise<string> {
  const deriveStretchedKey =
    options?.deriveStretchedKey ?? deriveStretchedKeyBytesAsync
  const accountSalt = deserializeArgon2Salt(accountSaltB64)
  const stretchedKey = await deriveStretchedKey(passphrase, accountSalt)
  return deriveOpaquePassword(stretchedKey)
}

/** Rewrap DEK under a new passphrase (passphrase change / recovery reset). */
export async function rewrapDekWithPassphrase(
  dek: VaultDek,
  newPassphrase: string,
  options?: { deriveStretchedKey?: StretchedKeyDeriver }
): Promise<PassphraseDerivedMaterial> {
  const deriveStretchedKey =
    options?.deriveStretchedKey ?? deriveStretchedKeyBytesAsync
  const accountSalt = randomSaltArgon2()
  const stretchedKey = await deriveStretchedKey(newPassphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const wrap = await wrapDekWithKek(dek, vaultKek)
  const vaultCrypto: VaultCrypto = {
    version: 2,
    accountSalt: serializeArgon2Salt(accountSalt),
    kdf: 'argon2id',
    memory: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
    vaultKeyWrap: {
      ciphertext: wrap.ciphertext,
      iv: wrap.iv,
    },
  }
  return {
    accountSalt,
    stretchedKey,
    vaultKek,
    opaquePassword,
    vaultCrypto,
    dek,
  }
}

export function parseVaultCrypto(encryptedVaultKey: string): VaultCrypto {
  const parsed: unknown = JSON.parse(encryptedVaultKey)
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'version' in parsed &&
    (parsed as { version: unknown }).version === 2 &&
    'vaultKeyWrap' in parsed &&
    'accountSalt' in parsed
  ) {
    return parsed as VaultCrypto
  }
  throw new Error('Unsupported vault crypto format')
}

export function serializeVaultCrypto(crypto: VaultCrypto): string {
  return JSON.stringify(crypto)
}

export function serializeKeyWrap(wrap: KeyWrap): string {
  return JSON.stringify(wrap)
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

/** Argon2 cost parameters are counts: 0, negatives and fractions are junk. */
function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0
}

export function parseKeyWrap(raw: string): KeyWrap {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('Invalid key wrap JSON')
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    throw new Error('Invalid key wrap shape')
  }
  const wrap = parsed as Record<string, unknown>
  if (
    !isNonEmptyString(wrap.salt) ||
    !isPositiveInteger(wrap.iterations) ||
    wrap.kdf !== 'argon2id' ||
    !isNonEmptyString(wrap.ciphertext) ||
    !isNonEmptyString(wrap.iv)
  ) {
    throw new Error('Invalid key wrap fields')
  }
  if (wrap.memory !== undefined && !isPositiveInteger(wrap.memory)) {
    throw new Error('Invalid key wrap memory')
  }
  if (wrap.parallelism !== undefined && !isPositiveInteger(wrap.parallelism)) {
    throw new Error('Invalid key wrap parallelism')
  }
  return {
    salt: wrap.salt,
    iterations: wrap.iterations,
    kdf: 'argon2id',
    memory: wrap.memory as number | undefined,
    parallelism: wrap.parallelism as number | undefined,
    ciphertext: wrap.ciphertext,
    iv: wrap.iv,
  }
}

/** Build a KeyWrap for recipient/device using Argon2id KEK from a secret. */
export async function wrapDekWithSecret(
  dek: VaultDek,
  secret: string
): Promise<KeyWrap> {
  const salt = randomSaltArgon2()
  const kek = await deriveVaultKeyArgon2(secret, salt)
  const payload = await wrapDekWithKek(dek, kek)
  return {
    salt: serializeArgon2Salt(salt),
    iterations: ARGON2_ITERATIONS,
    kdf: 'argon2id',
    memory: ARGON2_MEMORY_KIB,
    parallelism: ARGON2_PARALLELISM,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
  }
}

export async function unwrapDekWithSecret(
  wrap: KeyWrap,
  secret: string
): Promise<VaultDek> {
  assertSupportedArgon2Params(wrap)
  const kek = await deriveVaultKeyArgon2(
    secret,
    deserializeArgon2Salt(wrap.salt)
  )
  return unwrapDekWithKek({ ciphertext: wrap.ciphertext, iv: wrap.iv }, kek)
}

/**
 * Encrypt a vault field under the vault key.
 *
 * `additionalData` binds the ciphertext to its context (see `vaultFieldAad`),
 * so a blob cannot be lifted from one field or record and replayed into
 * another. It is optional because ciphertext already stored without it stays
 * decryptable only when decrypted the same way: AAD is covered by the GCM
 * tag, so adopting it for an existing field is a re-encrypt migration, not a
 * flag flip. New fields should pass it from the start.
 */
export async function encryptVaultSecret(
  plaintext: string,
  vaultKey: CryptoKey,
  options?: { additionalData?: string }
): Promise<EncryptedPayload> {
  return encryptUtf8(plaintext, vaultKey, options)
}

export async function decryptVaultSecret(
  payload: EncryptedPayload,
  vaultKey: CryptoKey,
  options?: { additionalData?: string }
): Promise<string> {
  return decryptUtf8(payload, vaultKey, options)
}
