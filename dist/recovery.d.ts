import { StretchedKeyDeriver } from './argon2.js';
import { KeyWrap, VaultDek } from './vault.js';
import './aes-gcm.js';

/**
 * Generate a BIP39 mnemonic (12 words = 128 bits entropy by default).
 */
declare function generateRecoveryPhrase(wordCount?: 12 | 15 | 18 | 21 | 24): string;
/**
 * Canonical form for KDF input: trimmed, lowercase, single spaces. Generated
 * mnemonics are already canonical, so normalizing here keeps every historical
 * wrap unlockable while making typed input (extra spaces, mixed case, line
 * breaks from a printed kit) derive the same key.
 */
declare function normalizeRecoveryPhrase(phrase: string): string;
declare function isValidRecoveryPhrase(phrase: string): boolean;
/** Salt length for the recovery auth derivation, in bytes. */
declare const RECOVERY_SALT_LENGTH = 16;
/**
 * Random salt for the recovery auth derivation, base64 for storage/transport.
 *
 * This salt MUST be stored alongside the recovery credential and MUST NOT be
 * derived from the vault's `accountSalt`: `rewrapDekWithPassphrase` mints a
 * fresh `accountSalt` on every passphrase change, which would silently
 * re-point this derivation at a salt the credential was never created with.
 */
declare function randomRecoverySalt(): string;
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
declare function deriveRecoveryOpaquePassword(phrase: string, recoverySaltB64: string): Promise<string>;
declare function wrapDekWithRecoveryPhrase(dek: VaultDek, phrase: string, deriveStretchedKey?: StretchedKeyDeriver): Promise<KeyWrap>;
declare function unlockDekWithRecovery(phrase: string, wrap: KeyWrap, deriveStretchedKey?: StretchedKeyDeriver): Promise<VaultDek>;

export { RECOVERY_SALT_LENGTH, deriveRecoveryOpaquePassword, generateRecoveryPhrase, isValidRecoveryPhrase, normalizeRecoveryPhrase, randomRecoverySalt, unlockDekWithRecovery, wrapDekWithRecoveryPhrase };
