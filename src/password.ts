/**
 * UI / policy minimum for unified and recipient passwords.
 *
 * Eight, lowered from twelve on 2026-08-22 at the product owner's direction,
 * to take friction out of sign-up and onboarding.
 *
 * Read this before raising or lowering it again. This value is not a login
 * policy. It is the floor on the input to Argon2id, and the key it derives
 * wraps the vault DEK, so an attacker holding the database grinds it offline
 * with no rate limit in the way. `ARGON2_MEMORY_KIB` 65536 with three
 * iterations buys roughly four orders of magnitude over a fast hash; it does
 * not rescue a password that is already on a wordlist. Nothing else in the
 * product compensates: there is no strength meter that blocks, no common
 * password list, and no composition rule.
 */
export const PASSWORD_MIN_LENGTH = 8

/** UI / policy maximum (characters after NFC). */
export const PASSWORD_MAX_LENGTH = 128

/**
 * Hard cap on UTF-8 bytes at the KDF boundary (DoS guard).
 * Larger than the UI max so multi-byte characters remain allowed.
 */
export const PASSWORD_HARD_MAX_BYTES = 1024

/** C0 + DEL + C1 controls. Printable symbols and spaces are allowed. */
const DISALLOWED_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u

export type PasswordPolicyErrorCode =
  | 'too_short'
  | 'too_long'
  | 'control_chars'

/** NFC so the same visual password always yields the same KDF bytes. */
export function normalizePassword(password: string): string {
  return password.normalize('NFC')
}

export function containsDisallowedPasswordChars(password: string): boolean {
  return DISALLOWED_CONTROL_CHARS.test(password)
}

export function getPasswordPolicyError(
  password: string
): PasswordPolicyErrorCode | null {
  const normalized = normalizePassword(password)
  if (normalized.length < PASSWORD_MIN_LENGTH) return 'too_short'
  if (normalized.length > PASSWORD_MAX_LENGTH) return 'too_long'
  if (containsDisallowedPasswordChars(normalized)) return 'control_chars'
  return null
}

export function passwordPolicyErrorMessage(
  code: PasswordPolicyErrorCode
): string {
  switch (code) {
    case 'too_short':
      return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`
    case 'too_long':
      return `Password must be at most ${PASSWORD_MAX_LENGTH} characters`
    case 'control_chars':
      return 'Password cannot include control characters'
  }
}

/** True when the value satisfies create/change policy (after NFC). */
export function isPasswordPolicySatisfied(password: string): boolean {
  return getPasswordPolicyError(password) === null
}

/**
 * Prepare a password for Argon2 / OPAQUE material derivation.
 * Throws if the UTF-8 encoding exceeds the hard DoS cap.
 */
export function preparePasswordForKdf(password: string): string {
  const normalized = normalizePassword(password)
  const byteLength = new TextEncoder().encode(normalized).byteLength
  if (byteLength > PASSWORD_HARD_MAX_BYTES) {
    throw new Error('Password is too long')
  }
  return normalized
}
