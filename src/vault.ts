import { encryptUtf8, decryptUtf8, type EncryptedPayload } from './aes-gcm'
import { bytesToBase64, base64ToBytes } from './encoding'
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveStretchedKeyBytes,
  deriveVaultKeyArgon2,
  randomSaltArgon2,
  serializeArgon2Salt,
  deserializeArgon2Salt,
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
export type VaultCryptoV2 = {
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
  kek: CryptoKey
): Promise<EncryptedPayload> {
  const raw = await exportDekRaw(dek)
  return encryptUtf8(bytesToBase64(raw), kek)
}

export async function unwrapDekWithKek(
  wrap: EncryptedPayload,
  kek: CryptoKey
): Promise<VaultDek> {
  const rawB64 = await decryptUtf8(wrap, kek)
  return importDekFromRaw(base64ToBytes(rawB64))
}

export type PassphraseDerivedMaterial = {
  accountSalt: Uint8Array
  stretchedKey: Uint8Array
  vaultKek: CryptoKey
  opaquePassword: string
  vaultCrypto: VaultCryptoV2
  dek: VaultDek
}

/** Create a new vault: random DEK + passphrase wrap + OPAQUE password material. */
export async function createVaultCryptoV2(
  passphrase: string,
  options?: { accountSaltB64?: string }
): Promise<PassphraseDerivedMaterial> {
  const accountSalt = options?.accountSaltB64
    ? deserializeArgon2Salt(options.accountSaltB64)
    : randomSaltArgon2()
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const dek = await generateVaultDek()
  const wrap = await wrapDekWithKek(dek, vaultKek)
  const vaultCrypto: VaultCryptoV2 = {
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

/** Unlock vault DEK from passphrase + stored crypto blob. */
export async function unlockVaultCryptoV2(
  passphrase: string,
  cryptoBlob: VaultCryptoV2
): Promise<{ dek: VaultDek; opaquePassword: string; vaultKek: CryptoKey }> {
  const accountSalt = deserializeArgon2Salt(cryptoBlob.accountSalt)
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const dek = await unwrapDekWithKek(cryptoBlob.vaultKeyWrap, vaultKek)
  return { dek, opaquePassword, vaultKek }
}

/** Derive OPAQUE password only (login without unwrap). */
export async function deriveOpaquePasswordFromPassphrase(
  passphrase: string,
  accountSaltB64: string
): Promise<string> {
  const accountSalt = deserializeArgon2Salt(accountSaltB64)
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt)
  return deriveOpaquePassword(stretchedKey)
}

/** Rewrap DEK under a new passphrase (passphrase change / recovery reset). */
export async function rewrapDekWithPassphrase(
  dek: VaultDek,
  newPassphrase: string
): Promise<PassphraseDerivedMaterial> {
  const accountSalt = randomSaltArgon2()
  const stretchedKey = deriveStretchedKeyBytes(newPassphrase, accountSalt)
  const vaultKek = await deriveVaultKek(stretchedKey)
  const opaquePassword = await deriveOpaquePassword(stretchedKey)
  const wrap = await wrapDekWithKek(dek, vaultKek)
  const vaultCrypto: VaultCryptoV2 = {
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

export function parseVaultCrypto(encryptedVaultKey: string): VaultCryptoV2 {
  const parsed: unknown = JSON.parse(encryptedVaultKey)
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'version' in parsed &&
    (parsed as { version: unknown }).version === 2 &&
    'vaultKeyWrap' in parsed &&
    'accountSalt' in parsed
  ) {
    return parsed as VaultCryptoV2
  }
  throw new Error('Unsupported vault crypto format')
}

export function serializeVaultCryptoV2(crypto: VaultCryptoV2): string {
  return JSON.stringify(crypto)
}

export function serializeKeyWrap(wrap: KeyWrap): string {
  return JSON.stringify(wrap)
}

export function parseKeyWrap(raw: string): KeyWrap {
  return JSON.parse(raw) as KeyWrap
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
  if (wrap.kdf !== 'argon2id') {
    throw new Error('Unsupported key wrap KDF')
  }
  const kek = await deriveVaultKeyArgon2(
    secret,
    deserializeArgon2Salt(wrap.salt)
  )
  return unwrapDekWithKek({ ciphertext: wrap.ciphertext, iv: wrap.iv }, kek)
}

export async function encryptVaultSecret(
  plaintext: string,
  vaultKey: CryptoKey
): Promise<EncryptedPayload> {
  return encryptUtf8(plaintext, vaultKey)
}

export async function decryptVaultSecret(
  payload: EncryptedPayload,
  vaultKey: CryptoKey
): Promise<string> {
  return decryptUtf8(payload, vaultKey)
}
