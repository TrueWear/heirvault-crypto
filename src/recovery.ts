import { generateMnemonic, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { encryptUtf8, decryptUtf8 } from './aes-gcm'
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveVaultKeyArgon2,
  randomSaltArgon2,
  serializeArgon2Salt,
  deserializeArgon2Salt,
  type StretchedKeyDeriver,
} from './argon2'
import { bytesToBase64, base64ToBytes } from './encoding'
import {
  assertSupportedArgon2Params,
  exportDekRaw,
  importDekFromRaw,
  type KeyWrap,
  type VaultDek,
} from './vault'

/**
 * Generate a BIP39 mnemonic (12 words = 128 bits entropy by default).
 */
export function generateRecoveryPhrase(
  wordCount: 12 | 15 | 18 | 21 | 24 = 12
): string {
  const strength = (wordCount / 3) * 32
  return generateMnemonic(wordlist, strength)
}

/**
 * Canonical form for KDF input: trimmed, lowercase, single spaces. Generated
 * mnemonics are already canonical, so normalizing here keeps every historical
 * wrap unlockable while making typed input (extra spaces, mixed case, line
 * breaks from a printed kit) derive the same key.
 */
export function normalizeRecoveryPhrase(phrase: string): string {
  return phrase.trim().toLowerCase().replace(/\s+/g, ' ')
}

export function isValidRecoveryPhrase(phrase: string): boolean {
  return validateMnemonic(normalizeRecoveryPhrase(phrase), wordlist)
}

export async function wrapDekWithRecoveryPhrase(
  dek: VaultDek,
  phrase: string,
  deriveStretchedKey?: StretchedKeyDeriver
): Promise<KeyWrap> {
  const salt = randomSaltArgon2()
  const kek = await deriveVaultKeyArgon2(
    normalizeRecoveryPhrase(phrase),
    salt,
    deriveStretchedKey
  )
  const raw = await exportDekRaw(dek)
  const payload = await encryptUtf8(bytesToBase64(raw), kek)
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

async function unlockWithPhrase(
  phrase: string,
  wrap: KeyWrap,
  salt: Uint8Array,
  deriveStretchedKey?: StretchedKeyDeriver
): Promise<VaultDek> {
  const kek = await deriveVaultKeyArgon2(phrase, salt, deriveStretchedKey)
  const rawB64 = await decryptUtf8(
    { ciphertext: wrap.ciphertext, iv: wrap.iv },
    kek
  )
  return importDekFromRaw(base64ToBytes(rawB64))
}

export async function unlockDekWithRecovery(
  phrase: string,
  wrap: KeyWrap,
  deriveStretchedKey?: StretchedKeyDeriver
): Promise<VaultDek> {
  assertSupportedArgon2Params(wrap)
  const salt = deserializeArgon2Salt(wrap.salt)
  const normalized = normalizeRecoveryPhrase(phrase)
  try {
    return await unlockWithPhrase(normalized, wrap, salt, deriveStretchedKey)
  } catch (normalizedError) {
    // Pre-normalization wraps derived the KEK from the raw typed phrase.
    // Retry once so those kits remain unlockable after canonicalize-on-unlock.
    if (phrase === normalized) {
      throw normalizedError
    }
    try {
      return await unlockWithPhrase(phrase, wrap, salt, deriveStretchedKey)
    } catch {
      throw normalizedError
    }
  }
}
