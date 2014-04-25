/**
 * Base64url encoding/decoding module.
 *
 * @module base64url
 */

/**
 * Adds base64 padding characters back to a base64url-encoded string.
 *
 * @function addPaddingCharacters
 *
 * @param {String} base64urlString The input base64url-encoded string
 *
 * @returns {String} The input string with optional added base64 padding characters
 */
addPaddingCharacters = function(base64urlString) {
    switch (base64urlString.length % 4) {
        case 0:
            return base64urlString;
        case 2:
            return base64urlString + "==";
        case 3:
            return base64urlString + "=";
        default:
            throw new Error("Invalid base64 string");
    }
};

/**
 * Converts a base64-encoded string into base64url.
 *
 * @function fromBase64String
 *
 * @param {String} base64String The input base64-encoded string to convert
 *
 * @returns {String} The input string converted to base64url
 */
exports.fromBase64String = function(base64String) {
    return base64String
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
};

/**
 * Converts a base64url-encoded string into base64.
 *
 * @function toBase64String
 *
 * @param {string} base64urlString The input base64url-encoded string to convert
 *
 * @returns {string} The input string converted to base64
 */
exports.toBase64String = function(base64urlString) {
    return addPaddingCharacters(base64urlString)
        .replace(/\-/, '+')
        .replace(/_/, '/');
};
