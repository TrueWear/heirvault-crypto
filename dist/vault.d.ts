import { EncryptedPayload } from './aes-gcm.js';

type KdfType = 'argon2id';
/** Wrap of a random DEK under a KEK (passphrase, recovery, recipient, or device). */
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
type VaultCryptoV2 = {
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
declare function wrapDekWithKek(dek: VaultDek, kek: CryptoKey): Promise<EncryptedPayload>;
declare function unwrapDekWithKek(wrap: EncryptedPayload, kek: CryptoKey): Promise<VaultDek>;
type PassphraseDerivedMaterial = {
    accountSalt: Uint8Array;
    stretchedKey: Uint8Array;
    vaultKek: CryptoKey;
    opaquePassword: string;
    vaultCrypto: VaultCryptoV2;
    dek: VaultDek;
};
/** Create a new vault: random DEK + passphrase wrap + OPAQUE password material. */
declare function createVaultCryptoV2(passphrase: string, options?: {
    accountSaltB64?: string;
}): Promise<PassphraseDerivedMaterial>;
/**
 * Reject unknown or weakened Argon2 suites. Stored params must match the
 * supported constants (advisory fields are not used for derivation yet).
 */
declare function assertSupportedArgon2Params(cryptoBlob: {
    kdf: string;
    memory?: number;
    iterations?: number;
    parallelism?: number;
}): void;
/** Unlock vault DEK from passphrase + stored crypto blob. */
declare function unlockVaultCryptoV2(passphrase: string, cryptoBlob: VaultCryptoV2): Promise<{
    dek: VaultDek;
    opaquePassword: string;
    vaultKek: CryptoKey;
}>;
/** Derive OPAQUE password only (login without unwrap). */
declare function deriveOpaquePasswordFromPassphrase(passphrase: string, accountSaltB64: string): Promise<string>;
/** Rewrap DEK under a new passphrase (passphrase change / recovery reset). */
declare function rewrapDekWithPassphrase(dek: VaultDek, newPassphrase: string): Promise<PassphraseDerivedMaterial>;
declare function parseVaultCrypto(encryptedVaultKey: string): VaultCryptoV2;
declare function serializeVaultCryptoV2(crypto: VaultCryptoV2): string;
declare function serializeKeyWrap(wrap: KeyWrap): string;
declare function parseKeyWrap(raw: string): KeyWrap;
/** Build a KeyWrap for recipient/device using Argon2id KEK from a secret. */
declare function wrapDekWithSecret(dek: VaultDek, secret: string): Promise<KeyWrap>;
declare function unwrapDekWithSecret(wrap: KeyWrap, secret: string): Promise<VaultDek>;
declare function encryptVaultSecret(plaintext: string, vaultKey: CryptoKey): Promise<EncryptedPayload>;
declare function decryptVaultSecret(payload: EncryptedPayload, vaultKey: CryptoKey): Promise<string>;

export { type KdfType, type KeyWrap, type PassphraseDerivedMaterial, type VaultCryptoV2, type VaultDek, assertSupportedArgon2Params, createVaultCryptoV2, decryptVaultSecret, deriveOpaquePasswordFromPassphrase, encryptVaultSecret, exportDekRaw, generateVaultDek, importDekFromRaw, parseKeyWrap, parseVaultCrypto, rewrapDekWithPassphrase, serializeKeyWrap, serializeVaultCryptoV2, unlockVaultCryptoV2, unwrapDekWithKek, unwrapDekWithSecret, wrapDekWithKek, wrapDekWithSecret };
