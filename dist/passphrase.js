// src/passphrase.ts
var PASSPHRASE_MIN_LENGTH = 12;
var PASSPHRASE_MAX_LENGTH = 128;
var PASSPHRASE_HARD_MAX_BYTES = 1024;
var DISALLOWED_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u;
function normalizePassphrase(passphrase) {
  return passphrase.normalize("NFC");
}
function containsDisallowedPassphraseChars(passphrase) {
  return DISALLOWED_CONTROL_CHARS.test(passphrase);
}
function getPassphrasePolicyError(passphrase) {
  const normalized = normalizePassphrase(passphrase);
  if (normalized.length < PASSPHRASE_MIN_LENGTH) return "too_short";
  if (normalized.length > PASSPHRASE_MAX_LENGTH) return "too_long";
  if (containsDisallowedPassphraseChars(normalized)) return "control_chars";
  return null;
}
function passphrasePolicyErrorMessage(code) {
  switch (code) {
    case "too_short":
      return `Passphrase must be at least ${PASSPHRASE_MIN_LENGTH} characters`;
    case "too_long":
      return `Passphrase must be at most ${PASSPHRASE_MAX_LENGTH} characters`;
    case "control_chars":
      return "Passphrase cannot include control characters";
  }
}
function isPassphrasePolicySatisfied(passphrase) {
  return getPassphrasePolicyError(passphrase) === null;
}
function preparePassphraseForKdf(passphrase) {
  const normalized = normalizePassphrase(passphrase);
  const byteLength = new TextEncoder().encode(normalized).byteLength;
  if (byteLength > PASSPHRASE_HARD_MAX_BYTES) {
    throw new Error("Passphrase is too long");
  }
  return normalized;
}
export {
  PASSPHRASE_HARD_MAX_BYTES,
  PASSPHRASE_MAX_LENGTH,
  PASSPHRASE_MIN_LENGTH,
  containsDisallowedPassphraseChars,
  getPassphrasePolicyError,
  isPassphrasePolicySatisfied,
  normalizePassphrase,
  passphrasePolicyErrorMessage,
  preparePassphraseForKdf
};
//# sourceMappingURL=passphrase.js.map