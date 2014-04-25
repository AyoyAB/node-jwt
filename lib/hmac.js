/**
 * HMAC calculator module.
 *
 * @module hmac
 */

var crypto = require('crypto');

/**
 * Supported HMAC algorithms.
 *
 * @enum algorithm
 */
exports.algorithm = {
    /** - HMAC with SHA-224 */
    'HMAC-SHA224': 'sha224',
    /** - HMAC with SHA-256 */
    'HMAC-SHA256': 'sha256',
    /** - HMAC with SHA-384 */
    'HMAC-SHA384': 'sha384',
    /** - HMAC with SHA-512 */
    'HMAC-SHA512': 'sha512'
};

/**
 * Performs an HMAC of the specified payload Buffer using the supplied key Buffer with the specified algorithm.
 *
 * @function doHmac
 *
 * @param {String}  algorithm       The digest algorithm to use
 * @param {Buffer}  keyBuffer       The cryptographic key to use
 * @param {Buffer}  payloadBuffer   The payload to HMAC
 *
 * @returns {Buffer} The generated Message Authentication Code
 */
exports.doHmac = function(algorithm, keyBuffer, payloadBuffer) {
    var hmac = crypto.createHmac(algorithm, keyBuffer);
    hmac.update(payloadBuffer);
    return hmac.digest();
};
