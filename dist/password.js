// src/password.ts
var PASSWORD_MIN_LENGTH = 8;
var PASSWORD_MAX_LENGTH = 128;
var PASSWORD_HARD_MAX_BYTES = 1024;
var DISALLOWED_CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u;
function normalizePassword(password) {
  return password.normalize("NFC");
}
function containsDisallowedPasswordChars(password) {
  return DISALLOWED_CONTROL_CHARS.test(password);
}
function getPasswordPolicyError(password) {
  const normalized = normalizePassword(password);
  if (normalized.length < PASSWORD_MIN_LENGTH) return "too_short";
  if (normalized.length > PASSWORD_MAX_LENGTH) return "too_long";
  if (containsDisallowedPasswordChars(normalized)) return "control_chars";
  return null;
}
function passwordPolicyErrorMessage(code) {
  switch (code) {
    case "too_short":
      return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
    case "too_long":
      return `Password must be at most ${PASSWORD_MAX_LENGTH} characters`;
    case "control_chars":
      return "Password cannot include control characters";
  }
}
function isPasswordPolicySatisfied(password) {
  return getPasswordPolicyError(password) === null;
}
function preparePasswordForKdf(password) {
  const normalized = normalizePassword(password);
  const byteLength = new TextEncoder().encode(normalized).byteLength;
  if (byteLength > PASSWORD_HARD_MAX_BYTES) {
    throw new Error("Password is too long");
  }
  return normalized;
}
export {
  PASSWORD_HARD_MAX_BYTES,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  containsDisallowedPasswordChars,
  getPasswordPolicyError,
  isPasswordPolicySatisfied,
  normalizePassword,
  passwordPolicyErrorMessage,
  preparePasswordForKdf
};
//# sourceMappingURL=password.js.map