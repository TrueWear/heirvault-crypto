import { StretchedKeyDeriver } from './argon2.js';
import { VaultDek, KeyWrap } from './vault.js';
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
/**
 * Guard the 128-bit-entropy assumption the recovery auth derivation rests on.
 * A BIP39 checksum is not a proof of entropy, but it does reject the case
 * that actually matters: a phrase a human made up rather than one we
 * generated.
 */
declare function assertGeneratedRecoveryPhrase(phrase: string): void;
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
 * Decode a stored recovery salt, rejecting any length but the one we mint.
 *
 * An empty string is valid base64, so without this an absent or truncated
 * salt column would decode to zero bytes and HKDF-Extract would fall back to
 * an all-zero salt -- turning a per-account auth secret into a global,
 * precomputable one. Mirrors `deserializeArgon2Salt`.
 */
declare function deserializeRecoverySalt(encoded: string): Uint8Array;
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
type RecoveryUnlockResult = {
    dek: VaultDek;
    /**
     * True when the wrap only opened under the raw typed phrase, i.e. it was
     * created before wrap and unlock shared normalizeRecoveryPhrase (library
     * commits before 2026-08-05). Callers should re-wrap under the normalized
     * phrase when they see this, which is what lets the fallback below be
     * retired instead of running forever.
     */
    usedLegacyRawPhrase: boolean;
};
/**
 * Unlock and report which form of the phrase worked.
 *
 * Prefer this over `unlockDekWithRecovery` where a re-wrap is possible: the
 * raw-phrase retry is a compatibility shim for a narrow window of
 * pre-normalization kits, and without anyone acting on this flag it is
 * permanent, costing a second full 64 MiB derivation on every failed unlock
 * of a non-canonical phrase.
 */
declare function unlockDekWithRecoveryDetailed(phrase: string, wrap: KeyWrap, deriveStretchedKey?: StretchedKeyDeriver): Promise<RecoveryUnlockResult>;
declare function unlockDekWithRecovery(phrase: string, wrap: KeyWrap, deriveStretchedKey?: StretchedKeyDeriver): Promise<VaultDek>;

export { RECOVERY_SALT_LENGTH, type RecoveryUnlockResult, assertGeneratedRecoveryPhrase, deriveRecoveryOpaquePassword, deserializeRecoverySalt, generateRecoveryPhrase, isValidRecoveryPhrase, normalizeRecoveryPhrase, randomRecoverySalt, unlockDekWithRecovery, unlockDekWithRecoveryDetailed, wrapDekWithRecoveryPhrase };
