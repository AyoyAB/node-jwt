/**
 * JSON Web Signature signing/validation module.
 *
 * @module jws
 */

var hmac      = require('./hmac');
var base64url = require('./base64url');

/**
 * Signing algorithms.
 *
 * @enum algorithm
 */
exports.algorithm = {
    /** HMAC with SHA-256 */
    HmacWithSha256: 'HS256',
    /** RSA with PKCS#1 v 1.5 padding and SHA-256 */
    RsaSsaWithSha256: 'RS256',
    /** ECDSA with Suite B elliptic curve P-256 and SHA-256 */
    EcdsaP256WithSha256: 'ES256'
};

/**
 * Returns the corresponding HMAC algorithm for a given JWA algorithm.
 *
 * @function getMacAlgorithm
 *
 * @param {algorithm} algorithm A JWA algorithm
 *
 * @returns {String} The corresponding HMAC algorithm
 */
var getMacAlgorithm = function(algorithm) {
    switch (algorithm) {
        case exports.algorithm.HmacWithSha256:
            return hmac.algorithm['HMAC-SHA256'];
        default:
            throw new Error('Unsupported algorithm: ' + algorithm);
    }
};

/**
 * Creates a JWS HMAC.
 *
 * @function createHmac
 *
 * @param {algorithm} algorithm     The JWA algorithm
 * @param {String} key              The HMAC key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 *
 * @returns {String} The JWS HMAC
 */
exports.createHmac = function(algorithm, key, protectedHeader, payload) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = new Buffer(base64url.toBase64String(key), 'base64');
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload, 'binary');
    return base64url.fromBase64String(hmac.doHmac(macAlgorithm, keyBuffer, payloadBuffer).toString('base64'));
};

/**
 * Validates a JWS HMAC.
 *
 * @function validateHmac
 *
 * @param {algorithm} algorithm     The JWA algorithm
 * @param {String} key              The HMAC key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 * @param {String} expectedHmac     The expected HMAC
 *
 * @returns {Boolean} True if the JWS HMAC is valid
 */
exports.validateHmac = function(algorithm, key, protectedHeader, payload, expectedHmac) {
    var actualHmac =  exports.createHmac(algorithm, key, protectedHeader, payload);

    return actualHmac === expectedHmac;
};
