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
declare const PASSWORD_MIN_LENGTH = 8;
/** UI / policy maximum (characters after NFC). */
declare const PASSWORD_MAX_LENGTH = 128;
/**
 * Hard cap on UTF-8 bytes at the KDF boundary (DoS guard).
 * Larger than the UI max so multi-byte characters remain allowed.
 */
declare const PASSWORD_HARD_MAX_BYTES = 1024;
type PasswordPolicyErrorCode = 'too_short' | 'too_long' | 'control_chars';
/** NFC so the same visual password always yields the same KDF bytes. */
declare function normalizePassword(password: string): string;
declare function containsDisallowedPasswordChars(password: string): boolean;
declare function getPasswordPolicyError(password: string): PasswordPolicyErrorCode | null;
declare function passwordPolicyErrorMessage(code: PasswordPolicyErrorCode): string;
/** True when the value satisfies create/change policy (after NFC). */
declare function isPasswordPolicySatisfied(password: string): boolean;
/**
 * Prepare a password for Argon2 / OPAQUE material derivation.
 * Throws if the UTF-8 encoding exceeds the hard DoS cap.
 */
declare function preparePasswordForKdf(password: string): string;

export { PASSWORD_HARD_MAX_BYTES, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, type PasswordPolicyErrorCode, containsDisallowedPasswordChars, getPasswordPolicyError, isPasswordPolicySatisfied, normalizePassword, passwordPolicyErrorMessage, preparePasswordForKdf };
