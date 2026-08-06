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
declare function wrapDekWithRecoveryPhrase(dek: VaultDek, phrase: string): Promise<KeyWrap>;
declare function unlockDekWithRecovery(phrase: string, wrap: KeyWrap): Promise<VaultDek>;

export { generateRecoveryPhrase, isValidRecoveryPhrase, normalizeRecoveryPhrase, unlockDekWithRecovery, wrapDekWithRecoveryPhrase };
