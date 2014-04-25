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
 * @param {String} algorithm A JWA algorithm
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
 * @param {String} algorithm        The JWA algorithm
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
 * @param {String} algorithm        The JWA algorithm
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

/**
 * Encodes a JSON Web Token.
 *
 * @function encodeJws
 *
 * @param {Object}  protectedHeader The JWS protected header
 * @param {String}  payload         The serialized payload
 * @param {String}  base64UrlKey    The base64url-encoded key
 *
 * @returns {String} The encoded JSON Web Token
 */
exports.encodeJws = function(protectedHeader, payload, base64UrlKey) {
    if (!protectedHeader || !protectedHeader.alg) {
        throw new Error('alg parameter must be present in header');
    }

    var jsonHeader = JSON.stringify(protectedHeader);
    var base64UrlHeader = base64url.fromBase64String(new Buffer(jsonHeader).toString('base64'));

    var base64UrlPayload = base64url.fromBase64String(new Buffer(payload).toString('base64'));

    var base64UrlHmac = exports.createHmac(
        protectedHeader.alg,
        base64UrlKey,
        base64UrlHeader,
        base64UrlPayload
    );

    return base64UrlHeader + '.' + base64UrlPayload + '.' + base64UrlHmac;
};

/**
 * Validates a JSON Web Token.
 *
 * @function validateJws
 *
 * @param {String}  encodedJwt      The encoded JWT to validate
 * @param {String}  base64UrlKey    The base64url-encoded key
 *
 * @returns {Boolean} True if the JWT is valid
 */
exports.validateJws = function(encodedJwt, base64UrlKey) {
    var encodedComponents = encodedJwt.split('.');
    if (encodedComponents.length != 3) {
        throw new Error('Invalid JWS');
    }

    var base64UrlHeader = encodedComponents[0];
    var base64UrlPayload = encodedComponents[1];
    var base64UrlHmac = encodedComponents[2];

    var jsonHeader = new Buffer(base64url.toBase64String(base64UrlHeader), 'base64').toString();

    var header;
    try {
        header = JSON.parse(jsonHeader);
    } catch (e) {
        throw new Error('JWS protected header is not valid JSON');
    }

    return exports.validateHmac(header.alg, base64UrlKey, base64UrlHeader, base64UrlPayload, base64UrlHmac);
};
