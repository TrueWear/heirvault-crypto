/** UI / policy minimum for unified and recipient passphrases. */
declare const PASSPHRASE_MIN_LENGTH = 12;
/** UI / policy maximum (characters after NFC). */
declare const PASSPHRASE_MAX_LENGTH = 128;
/**
 * Hard cap on UTF-8 bytes at the KDF boundary (DoS guard).
 * Larger than the UI max so multi-byte characters remain allowed.
 */
declare const PASSPHRASE_HARD_MAX_BYTES = 1024;
type PassphrasePolicyErrorCode = 'too_short' | 'too_long' | 'control_chars';
/** NFC so the same visual passphrase always yields the same KDF bytes. */
declare function normalizePassphrase(passphrase: string): string;
declare function containsDisallowedPassphraseChars(passphrase: string): boolean;
declare function getPassphrasePolicyError(passphrase: string): PassphrasePolicyErrorCode | null;
declare function passphrasePolicyErrorMessage(code: PassphrasePolicyErrorCode): string;
/** True when the value satisfies create/change policy (after NFC). */
declare function isPassphrasePolicySatisfied(passphrase: string): boolean;
/**
 * Prepare a passphrase for Argon2 / OPAQUE material derivation.
 * Throws if the UTF-8 encoding exceeds the hard DoS cap.
 */
declare function preparePassphraseForKdf(passphrase: string): string;

export { PASSPHRASE_HARD_MAX_BYTES, PASSPHRASE_MAX_LENGTH, PASSPHRASE_MIN_LENGTH, type PassphrasePolicyErrorCode, containsDisallowedPassphraseChars, getPassphrasePolicyError, isPassphrasePolicySatisfied, normalizePassphrase, passphrasePolicyErrorMessage, preparePassphraseForKdf };
