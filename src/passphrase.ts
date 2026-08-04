/** UI / policy minimum for unified and recipient passphrases. */
export const PASSPHRASE_MIN_LENGTH = 12

/** UI / policy maximum (characters after NFC). */
export const PASSPHRASE_MAX_LENGTH = 128

/**
 * Hard cap on UTF-8 bytes at the KDF boundary (DoS guard).
 * Larger than the UI max so multi-byte characters remain allowed.
 */
export const PASSPHRASE_HARD_MAX_BYTES = 1024

/** C0 + DEL + C1 controls. Printable symbols and spaces are allowed. */
const DISALLOWED_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u

export type PassphrasePolicyErrorCode =
  | 'too_short'
  | 'too_long'
  | 'control_chars'

/** NFC so the same visual passphrase always yields the same KDF bytes. */
export function normalizePassphrase(passphrase: string): string {
  return passphrase.normalize('NFC')
}

export function containsDisallowedPassphraseChars(passphrase: string): boolean {
  return DISALLOWED_CONTROL_CHARS.test(passphrase)
}

export function getPassphrasePolicyError(
  passphrase: string
): PassphrasePolicyErrorCode | null {
  const normalized = normalizePassphrase(passphrase)
  if (normalized.length < PASSPHRASE_MIN_LENGTH) return 'too_short'
  if (normalized.length > PASSPHRASE_MAX_LENGTH) return 'too_long'
  if (containsDisallowedPassphraseChars(normalized)) return 'control_chars'
  return null
}

export function passphrasePolicyErrorMessage(
  code: PassphrasePolicyErrorCode
): string {
  switch (code) {
    case 'too_short':
      return `Passphrase must be at least ${PASSPHRASE_MIN_LENGTH} characters`
    case 'too_long':
      return `Passphrase must be at most ${PASSPHRASE_MAX_LENGTH} characters`
    case 'control_chars':
      return 'Passphrase cannot include control characters'
  }
}

/** True when the value satisfies create/change policy (after NFC). */
export function isPassphrasePolicySatisfied(passphrase: string): boolean {
  return getPassphrasePolicyError(passphrase) === null
}

/**
 * Prepare a passphrase for Argon2 / OPAQUE material derivation.
 * Throws if the UTF-8 encoding exceeds the hard DoS cap.
 */
export function preparePassphraseForKdf(passphrase: string): string {
  const normalized = normalizePassphrase(passphrase)
  const byteLength = new TextEncoder().encode(normalized).byteLength
  if (byteLength > PASSPHRASE_HARD_MAX_BYTES) {
    throw new Error('Passphrase is too long')
  }
  return normalized
}
