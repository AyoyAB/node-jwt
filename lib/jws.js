/**
 * JSON Web Signature signing/validation module.
 *
 * @module jws
 */

/*jshint node: true*/

"use strict";

var
    // Imports
    base64url = require('./base64url'),
    hmac      = require('./hmac'),
    jwk       = require('./jwk'),
    pubKey    = require('./pubkey'),
    // Objects
    signatureAlgorithm,
    // Functions
    getMacAlgorithm,
    createHmac,
    validateHmac,
    createSignature,
    validateSignature;


/**
 * Signing algorithms.
 * @readonly
 * @enum algorithm
 */
signatureAlgorithm = {
    /** HMAC with SHA-256 */
    HmacWithSha256: 'HS256',
    /** RSA with PKCS#1 v 1.5 padding and SHA-256 */
    RsaPkcs115WithSha256: 'RS256',
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
getMacAlgorithm = function(algorithm) {
    switch (algorithm) {
        case signatureAlgorithm.HmacWithSha256:
        case signatureAlgorithm.EcdsaP256WithSha256:
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
 * @param {Object} key              The HMAC JWK key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 *
 * @returns {String} The JWS HMAC
 */
createHmac = function(algorithm, key, protectedHeader, payload) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = jwk.jwkToOpenSSL(key);
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload);
    return base64url.fromBase64String(hmac.doHmac(macAlgorithm, keyBuffer, payloadBuffer).toString('base64'));
};

/**
 * Validates a JWS HMAC.
 *
 * @function validateHmac
 *
 * @param {algorithm} algorithm     The JWA algorithm
 * @param {Object} key              The HMAC key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 * @param {String} expectedHmac     The expected HMAC
 *
 * @returns {Boolean} True if the JWS HMAC is valid
 */
validateHmac = function(algorithm, key, protectedHeader, payload, expectedHmac) {
    var actualHmac =  createHmac(algorithm, key, protectedHeader, payload);

    return actualHmac === expectedHmac;
};

/**
 * Creates a JWS public key signature.
 *
 * @function createSignature
 *
 * @param {algorithm} algorithm     The JWA algorithm
 * @param {Object} key              The JWK private key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 *
 * @returns {String} The JWS public key signature
 */
createSignature = function(algorithm, key, protectedHeader, payload) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = jwk.jwkToOpenSSL(key);
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload);
    var derSignature = pubKey.doSign(macAlgorithm, keyBuffer, payloadBuffer);
    // TODO: Convert derSignature to JWS, omitting leading zeros.
    // The algorithm will tell us how long a signature to expect.
    // We need to check if this is ecdsa, and only then, to convert the signature!
    // Clean up the module while we're at it...
    return base64url.fromBase64String(derSignature.toString('base64'));
};

/**
 * Valdiates a JWS public key signature.
 *
 * @function validateSignature
 *
 * @param {algorithm} algorithm     The JWA algorithm
 * @param {Object} key              The JWK public key
 * @param {String} protectedHeader  The JWS protected header
 * @param {String} payload          The JWS payload
 * @param {String} signature        The JWS signature
 *
 * @returns {Boolean} True if the JWS signature is valid
 */
validateSignature = function(algorithm, key, protectedHeader, payload, signature) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = jwk.jwkToOpenSSL(key);
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload);
    var signatureBuffer = new Buffer(base64url.toBase64String(signature), 'base64');
    // TODO: Convert JWS to derSignature, adding leading zeros.
    // The algorithm will tell us how long a signature to expect.
    // We need to check if this is ecdsa, and only then, to convert the signature!
    return pubKey.doVerify(macAlgorithm, keyBuffer, payloadBuffer, signatureBuffer);
};

module.exports = {
    signatureAlgorithm: signatureAlgorithm,
    createHmac : createHmac,
    validateHmac : validateHmac,
    createSignature : createSignature,
    validateSignature : validateSignature
};
