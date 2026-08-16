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
import { HKDF_INFO_RECOVERY_AUTH, hkdfExtractExpand } from './hkdf'
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

/**
 * Guard the 128-bit-entropy assumption the recovery auth derivation rests on.
 * A BIP39 checksum is not a proof of entropy, but it does reject the case
 * that actually matters: a phrase a human made up rather than one we
 * generated.
 */
export function assertGeneratedRecoveryPhrase(phrase: string): void {
  if (!isValidRecoveryPhrase(phrase)) {
    throw new Error('Recovery phrase is not a valid BIP39 mnemonic')
  }
}

/** Salt length for the recovery auth derivation, in bytes. */
export const RECOVERY_SALT_LENGTH = 16

/**
 * Random salt for the recovery auth derivation, base64 for storage/transport.
 *
 * This salt MUST be stored alongside the recovery credential and MUST NOT be
 * derived from the vault's `accountSalt`: `rewrapDekWithPassphrase` mints a
 * fresh `accountSalt` on every passphrase change, which would silently
 * re-point this derivation at a salt the credential was never created with.
 */
export function randomRecoverySalt(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_LENGTH)))
}

/**
 * Decode a stored recovery salt, rejecting any length but the one we mint.
 *
 * An empty string is valid base64, so without this an absent or truncated
 * salt column would decode to zero bytes and HKDF-Extract would fall back to
 * an all-zero salt -- turning a per-account auth secret into a global,
 * precomputable one. Mirrors `deserializeArgon2Salt`.
 */
export function deserializeRecoverySalt(encoded: string): Uint8Array {
  const salt = base64ToBytes(encoded)
  if (salt.length !== RECOVERY_SALT_LENGTH) {
    throw new Error(`Invalid recovery salt length: ${salt.length}`)
  }
  return salt
}

/**
 * Derive the OPAQUE password used to authenticate with a recovery phrase.
 *
 * Deliberately HKDF and not Argon2id: a BIP39 phrase carries 128 bits of
 * entropy, so there is no low-entropy secret to stretch, and stretching here
 * would add a second 64 MiB derivation to the recovery sign-in path for no
 * security gain.
 *
 * This is fully domain-separated from vault unlock, which keeps Argon2id over
 * the phrase with the wrap's own salt (`unlockDekWithRecovery`). Neither
 * output is derivable from the other, and the wrap format is untouched, so
 * emergency kits printed before recovery sign-in existed stay unlockable.
 */
export async function deriveRecoveryOpaquePassword(
  phrase: string,
  recoverySaltB64: string
): Promise<string> {
  // The entire reason this is HKDF and not Argon2id is that the input is a
  // generated BIP39 mnemonic carrying 128 bits. Enforce that rather than
  // assuming it: HKDF applies no work factor, so a user-chosen phrase would
  // be enumerable at roughly one hash per guess by anyone holding the OPAQUE
  // registration record, and the recovered phrase also opens the vault wrap.
  assertGeneratedRecoveryPhrase(phrase)
  const ikm = new TextEncoder().encode(normalizeRecoveryPhrase(phrase))
  const authBytes = await hkdfExtractExpand(
    ikm,
    deserializeRecoverySalt(recoverySaltB64),
    HKDF_INFO_RECOVERY_AUTH
  )
  return bytesToBase64(authBytes)
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

export type RecoveryUnlockResult = {
  dek: VaultDek
  /**
   * True when the wrap only opened under the raw typed phrase, i.e. it was
   * created before wrap and unlock shared normalizeRecoveryPhrase (library
   * commits before 2026-08-05). Callers should re-wrap under the normalized
   * phrase when they see this, which is what lets the fallback below be
   * retired instead of running forever.
   */
  usedLegacyRawPhrase: boolean
}

/**
 * Unlock and report which form of the phrase worked.
 *
 * Prefer this over `unlockDekWithRecovery` where a re-wrap is possible: the
 * raw-phrase retry is a compatibility shim for a narrow window of
 * pre-normalization kits, and without anyone acting on this flag it is
 * permanent, costing a second full 64 MiB derivation on every failed unlock
 * of a non-canonical phrase.
 */
export async function unlockDekWithRecoveryDetailed(
  phrase: string,
  wrap: KeyWrap,
  deriveStretchedKey?: StretchedKeyDeriver
): Promise<RecoveryUnlockResult> {
  assertSupportedArgon2Params(wrap)
  const salt = deserializeArgon2Salt(wrap.salt)
  const normalized = normalizeRecoveryPhrase(phrase)
  try {
    return {
      dek: await unlockWithPhrase(normalized, wrap, salt, deriveStretchedKey),
      usedLegacyRawPhrase: false,
    }
  } catch (normalizedError) {
    // Pre-normalization wraps derived the KEK from the raw typed phrase.
    // Retry once so those kits remain unlockable after canonicalize-on-unlock.
    if (phrase === normalized) {
      throw normalizedError
    }
    try {
      return {
        dek: await unlockWithPhrase(phrase, wrap, salt, deriveStretchedKey),
        usedLegacyRawPhrase: true,
      }
      // Report the normalized failure either way: distinguishing "legacy wrap"
      // from "wrong phrase" would be an oracle.
    } catch {
      throw normalizedError
    }
  }
}

export async function unlockDekWithRecovery(
  phrase: string,
  wrap: KeyWrap,
  deriveStretchedKey?: StretchedKeyDeriver
): Promise<VaultDek> {
  const { dek } = await unlockDekWithRecoveryDetailed(
    phrase,
    wrap,
    deriveStretchedKey
  )
  return dek
}
