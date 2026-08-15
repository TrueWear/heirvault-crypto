type EncryptedPayload = {
    ciphertext: string;
    iv: string;
};
type AesGcmOptions = {
    /**
     * Additional authenticated data (context binding). Must match on decrypt.
     * Bind vaultId|itemId|field|kind (or similar) so ciphertext cannot be swapped
     * across rows/fields.
     */
    additionalData?: string | Uint8Array;
};
declare function encryptUtf8(plaintext: string, key: CryptoKey, options?: AesGcmOptions): Promise<EncryptedPayload>;
declare function decryptUtf8(payload: EncryptedPayload, key: CryptoKey, options?: AesGcmOptions): Promise<string>;
/** Encrypt binary for storage upload; ciphertext is raw bytes, iv is base64. */
declare function encryptBinary(plaintext: Uint8Array, key: CryptoKey, options?: AesGcmOptions): Promise<{
    ciphertext: Uint8Array;
    iv: string;
}>;
declare function decryptBinary(ciphertext: Uint8Array, ivBase64: string, key: CryptoKey, options?: AesGcmOptions): Promise<Uint8Array>;
/**
 * Canonical AAD string for vault/handoff field binding.
 *
 * Encoded as JSON rather than delimiter-joined so distinct (vaultId, itemId,
 * field, kind) tuples can never collide onto the same AAD string (e.g. a
 * naive `join('|')` lets field="x|y" collide with field="x", kind="y").
 */
declare function vaultFieldAad(parts: {
    vaultId: string;
    itemId: string;
    field: string;
    kind?: string;
}): string;

export { type AesGcmOptions, type EncryptedPayload, decryptBinary, decryptUtf8, encryptBinary, encryptUtf8, vaultFieldAad };
