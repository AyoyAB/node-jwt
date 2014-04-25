/** @module hmac */

var crypto = require('crypto');

/**
 * Performs a HMAC of the specified payload Buffer using the supplied key Buffer with the specified algorithm.
 *
 * @function
 * @param {String} algorithm - The digest algorithm to use.
 * @param {Buffer} keyBuffer - The HMAC key to use.
 * @param {Buffer} payloadBuffer - The payload to HMAC.
 * @returns {Buffer} The digest.
 */
exports.doHmac = function(algorithm, keyBuffer, payloadBuffer) {
    var hmac = crypto.createHmac(algorithm, keyBuffer);
    hmac.update(payloadBuffer);
    return hmac.digest();
};
