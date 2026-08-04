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
} from './argon2'
import { bytesToBase64, base64ToBytes } from './encoding'
import {
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

export function isValidRecoveryPhrase(phrase: string): boolean {
  return validateMnemonic(
    phrase.trim().toLowerCase().replace(/\s+/g, ' '),
    wordlist
  )
}

export async function wrapDekWithRecoveryPhrase(
  dek: VaultDek,
  phrase: string
): Promise<KeyWrap> {
  const salt = randomSaltArgon2()
  const kek = await deriveVaultKeyArgon2(phrase, salt)
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

export async function unlockDekWithRecovery(
  phrase: string,
  wrap: KeyWrap
): Promise<VaultDek> {
  if (wrap.kdf !== 'argon2id') {
    throw new Error('Unsupported recovery wrap KDF')
  }
  const salt = deserializeArgon2Salt(wrap.salt)
  const kek = await deriveVaultKeyArgon2(phrase, salt)
  const rawB64 = await decryptUtf8(
    { ciphertext: wrap.ciphertext, iv: wrap.iv },
    kek
  )
  return importDekFromRaw(base64ToBytes(rawB64))
}
