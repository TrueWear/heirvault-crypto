import { EncryptedPayload } from './aes-gcm.js';
import { StretchedKeyDeriver } from './argon2.js';

type KdfType = 'argon2id';
/** Wrap of a random DEK under a KEK (password, recovery, recipient, or device). */
type KeyWrap = {
    salt: string;
    iterations: number;
    kdf: KdfType;
    memory?: number;
    parallelism?: number;
    ciphertext: string;
    iv: string;
};
/** Vault crypto blob stored as JSON on the vault row. */
type VaultCrypto = {
    version: 2;
    accountSalt: string;
    kdf: 'argon2id';
    memory: number;
    iterations: number;
    parallelism: number;
    vaultKeyWrap: {
        ciphertext: string;
        iv: string;
    };
};
type VaultDek = CryptoKey;
declare function generateVaultDek(): Promise<VaultDek>;
declare function exportDekRaw(dek: VaultDek): Promise<Uint8Array>;
declare function importDekFromRaw(raw: Uint8Array, extractable?: boolean): Promise<VaultDek>;
declare function wrapDekWithKek(dek: VaultDek, kek: CryptoKey, options?: {
    additionalData?: string;
}): Promise<EncryptedPayload>;
declare function unwrapDekWithKek(wrap: EncryptedPayload, kek: CryptoKey, options?: {
    additionalData?: string;
}): Promise<VaultDek>;
type PasswordDerivedMaterial = {
    accountSalt: Uint8Array;
    stretchedKey: Uint8Array;
    vaultKek: CryptoKey;
    opaquePassword: string;
    vaultCrypto: VaultCrypto;
    dek: VaultDek;
};
/** Create a new vault: random DEK + password wrap + OPAQUE password material. */
declare function createVaultCrypto(password: string, options?: {
    accountSaltB64?: string;
    deriveStretchedKey?: StretchedKeyDeriver;
}): Promise<PasswordDerivedMaterial>;
/**
 * Reject unknown or weakened Argon2 suites.
 *
 * Read this precisely: it rejects a stored parameter that disagrees with the
 * supported suite, but a wrap that simply omits `memory`/`iterations`/
 * `parallelism` passes. That is safe only because derivation never consults
 * these fields -- `deriveVaultKeyArgon2` always uses the ARGON2_* module
 * constants -- so an attacker cannot weaken a derivation by editing or
 * dropping them. They are advisory, recorded so a future migration can tell
 * which suite produced a wrap.
 *
 * If derivation is ever changed to honor stored params, this check must
 * become mandatory-field validation first, or omitting a field turns into a
 * downgrade vector.
 */
declare function assertSupportedArgon2Params(cryptoBlob: {
    kdf: string;
    memory?: number;
    iterations?: number;
    parallelism?: number;
}): void;
/** Unlock vault DEK from password + stored crypto blob. */
declare function unlockVaultCrypto(password: string, cryptoBlob: VaultCrypto, options?: {
    deriveStretchedKey?: StretchedKeyDeriver;
}): Promise<{
    dek: VaultDek;
    opaquePassword: string;
    vaultKek: CryptoKey;
}>;
/** Derive OPAQUE password only (login without unwrap). */
declare function deriveOpaquePasswordForLogin(password: string, accountSaltB64: string, options?: {
    deriveStretchedKey?: StretchedKeyDeriver;
}): Promise<string>;
/** Rewrap DEK under a new password (password change / recovery reset). */
declare function rewrapDekWithPassword(dek: VaultDek, newPassword: string, options?: {
    deriveStretchedKey?: StretchedKeyDeriver;
}): Promise<PasswordDerivedMaterial>;
declare function parseVaultCrypto(encryptedVaultKey: string): VaultCrypto;
declare function serializeVaultCrypto(crypto: VaultCrypto): string;
declare function serializeKeyWrap(wrap: KeyWrap): string;
declare function parseKeyWrap(raw: string): KeyWrap;
/** Build a KeyWrap for recipient/device using Argon2id KEK from a secret. */
declare function wrapDekWithSecret(dek: VaultDek, secret: string): Promise<KeyWrap>;
declare function unwrapDekWithSecret(wrap: KeyWrap, secret: string): Promise<VaultDek>;
/**
 * Encrypt a vault field under the vault key.
 *
 * `additionalData` binds the ciphertext to its context (see `vaultFieldAad`),
 * so a blob cannot be lifted from one field or record and replayed into
 * another. It is optional because ciphertext already stored without it stays
 * decryptable only when decrypted the same way: AAD is covered by the GCM
 * tag, so adopting it for an existing field is a re-encrypt migration, not a
 * flag flip. New fields should pass it from the start.
 */
declare function encryptVaultSecret(plaintext: string, vaultKey: CryptoKey, options?: {
    additionalData?: string;
}): Promise<EncryptedPayload>;
declare function decryptVaultSecret(payload: EncryptedPayload, vaultKey: CryptoKey, options?: {
    additionalData?: string;
}): Promise<string>;

export { type KdfType, type KeyWrap, type PasswordDerivedMaterial, type VaultCrypto, type VaultDek, assertSupportedArgon2Params, createVaultCrypto, decryptVaultSecret, deriveOpaquePasswordForLogin, encryptVaultSecret, exportDekRaw, generateVaultDek, importDekFromRaw, parseKeyWrap, parseVaultCrypto, rewrapDekWithPassword, serializeKeyWrap, serializeVaultCrypto, unlockVaultCrypto, unwrapDekWithKek, unwrapDekWithSecret, wrapDekWithKek, wrapDekWithSecret };
