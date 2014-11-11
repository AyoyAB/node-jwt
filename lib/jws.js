/**
 * JSON Web Signature signing/validation module.
 *
 * @module jws
 */

/*jshint node: true*/

"use strict";

var
    // Imports
    asn1      = require('./asn1'),
    base64url = require('./base64url'),
    hmac      = require('./hmac'),
    jwk       = require('./jwk'),
    pubKey    = require('./pubkey'),
    // Objects
    signatureAlgorithm,
    // Functions
    getMacAlgorithm,
    isEcdsaAlgorithm,
    getSignatureParameterLength,
    trimOrPadIntegerBuffer,
    padIntegerBuffer,
    convertEcdsaSignatureToJws,
    convertJwsSignatureToEcdsa,
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
    /** ECDSA with Suite B elliptic curve P-256 and SHA-256 */
    EcdsaP256WithSha256: 'ES256',
    /** ECDSA with Suite B elliptic curve P-521 and SHA-512 */
    EcdsaP521WithSha512: 'ES512'
};

/**
 * Returns the corresponding HMAC algorithm for a given JWA algorithm.
 *
 * @function getMacAlgorithm
 *
 * @param {signatureAlgorithm} algorithm - A JWA signing algorithm
 *
 * @returns {String} The corresponding HMAC algorithm
 */
getMacAlgorithm = function(algorithm) {
    switch (algorithm) {
        case signatureAlgorithm.HmacWithSha256:
        case signatureAlgorithm.EcdsaP256WithSha256:
            return hmac.algorithm['HMAC-SHA256'];
        case signatureAlgorithm.EcdsaP521WithSha512:
            return hmac.algorithm['HMAC-SHA512'];
        default:
            throw new Error('Unsupported algorithm: ' + algorithm);
    }
};

/**
 * Checks if a signing algorithm is an ECDSA algorithm.
 *
 * @function isEcdsaAlgorithm
 *
 * @param {signatureAlgorithm} algorithm - A JWA signing algorithm
 *
 * @returns {boolean} True if the algorithm is a ECDSA algorithm
 */
isEcdsaAlgorithm = function(algorithm) {
    switch (algorithm) {
        case signatureAlgorithm.EcdsaP256WithSha256:
        case signatureAlgorithm.EcdsaP521WithSha512:
            return true;
        default:
            return false;
    }
};

/**
 * Returns the length of signature parameters for the specified algorithm.
 *
 * @function getSignatureParameterLength
 *
 * @param {signatureAlgorithm} algorithm - A JWA signing algorithm
 *
 * @returns {number} The signature parameter length
 */
getSignatureParameterLength = function(algorithm) {
    switch (algorithm) {
        case signatureAlgorithm.EcdsaP256WithSha256:
            return 32;
        case signatureAlgorithm.EcdsaP521WithSha512:
            return 66;
        default:
            throw new Error('Unsupported algorithm: ' + algorithm);
    }
};

/**
 * Trims or pads the input integer Buffer to the expected length.
 *
 * This is used to trim away leading zeroes added during ASN.1 encoding, optionally padding to the expected length..
 *
 * @function trimOrPadIntegerBuffer
 *
 * @param {Buffer} intBuffer        - The Buffer to trim
 * @param {number} requestedLength   - The requested length of the Buffer
 *
 * @returns {Buffer} The trimmed Buffer
 */
trimOrPadIntegerBuffer = function(intBuffer, requestedLength) {
    var offset, targetBuffer;
    if (requestedLength === intBuffer.length) {
        // Input buffer has correct length. Pass it on.
        return intBuffer;
    } else if (requestedLength > intBuffer.length) {
        // Input buffer too short. Pad it.
        targetBuffer = new Buffer(new Array(requestedLength));
        offset = requestedLength - intBuffer.length;
        intBuffer.copy(targetBuffer, offset, 0, intBuffer.length);
        return targetBuffer;
    } else {
        // Input buffer too long. Trim it.
        offset = intBuffer.length - requestedLength;
        targetBuffer = new Buffer(requestedLength);
        intBuffer.copy(targetBuffer, 0, offset, offset + requestedLength);
        return targetBuffer;
    }
};

/**
 * Pads the input integer Buffer with optional leading zeroes.
 *
 * This is used to restore leading zeroes needed during ASN.1 encoding.
 *
 * @function padIntegerBuffer
 *
 * @param {Buffer} intBuffer - The Buffer to pad
 *
 * @returns {Buffer} The padded Buffer
 */
padIntegerBuffer = function(intBuffer) {
    var paddedBuffer;

    if ((intBuffer[0] & 0x80)) {
        paddedBuffer = new Buffer(intBuffer.length + 1);
        paddedBuffer[0] = 0;
        intBuffer.copy(paddedBuffer, 1, 0, intBuffer.length);
        return paddedBuffer;
    }
    else {
        // The buffer doesn't need padding.
        return intBuffer;
    }
};

/**
 * Converts an RFC 5480 ECDSA-Sig-Value to JWS format.
 *
 * @param {Buffer} ecdsaSignature   - The signature to convert
 * @param {Buffer} algorithm        - The signature algorithm
 *
 * @returns {Buffer} The converted signature
 */
convertEcdsaSignatureToJws = function(ecdsaSignature, algorithm) {
    var decodedSignature = asn1.decodeDerEcdsaSignature(ecdsaSignature),
        r = trimOrPadIntegerBuffer(decodedSignature.r, getSignatureParameterLength(algorithm)),
        s = trimOrPadIntegerBuffer(decodedSignature.s, getSignatureParameterLength(algorithm));

    return Buffer.concat([ r, s ]);
};

/**
 * Converts a JWS signature to RFC 5480 ECDSA-Sig-Value format.
 *
 * @param {Buffer} jwsSignature - The signature to convert
 * @param {Buffer} algorithm    - The signature algorithm
 *
 * @returns {Buffer} The converted signature
 */
convertJwsSignatureToEcdsa = function(jwsSignature, algorithm) {
    var paramLen = getSignatureParameterLength(algorithm), r, s;
    if (jwsSignature.length != 2 * paramLen) {
        throw new Error('Input length not equal to double algorithm length: ' + paramLen + '(actual: ' + jwsSignature.length + ')');
    }

    r = padIntegerBuffer(jwsSignature.slice(0, paramLen));
    s = padIntegerBuffer(jwsSignature.slice(paramLen));

    return asn1.encodeEcdsaSignature(r, s);
};

/**
 * Creates a JWS HMAC.
 *
 * @function createHmac
 *
 * @param {signatureAlgorithm} algorithm    - The JWA algorithm
 * @param {Object} key                      - The HMAC JWK key
 * @param {String} protectedHeader          - The JWS protected header
 * @param {String} payload                  - The JWS payload
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
 * @param {signatureAlgorithm} algorithm    - The JWA algorithm
 * @param {Object} key                      - The HMAC key
 * @param {String} protectedHeader          - The JWS protected header
 * @param {String} payload                  - The JWS payload
 * @param {String} expectedHmac             - The expected HMAC
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
 * @param {signatureAlgorithm} algorithm    - The JWA algorithm
 * @param {Object} key                      - The JWK private key
 * @param {String} protectedHeader          - The JWS protected header
 * @param {String} payload                  - The JWS payload
 *
 * @returns {String} The JWS public key signature
 */
createSignature = function(algorithm, key, protectedHeader, payload) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = jwk.jwkToOpenSSL(key);
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload);
    var signatureBuffer = pubKey.doSign(macAlgorithm, keyBuffer, payloadBuffer);
    if (isEcdsaAlgorithm(algorithm)) {
        signatureBuffer = convertEcdsaSignatureToJws(signatureBuffer, algorithm);
    }
    return base64url.fromBase64String(signatureBuffer.toString('base64'));
};

/**
 * Valdiates a JWS public key signature.
 *
 * @function validateSignature
 *
 * @param {signatureAlgorithm} algorithm    - The JWA algorithm
 * @param {Object} key                      - The JWK public key
 * @param {String} protectedHeader          - The JWS protected header
 * @param {String} payload                  - The JWS payload
 * @param {String} signature                - The JWS signature
 *
 * @returns {Boolean} True if the JWS signature is valid
 */
validateSignature = function(algorithm, key, protectedHeader, payload, signature) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = jwk.jwkToOpenSSL(key);
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload);
    var signatureBuffer = new Buffer(base64url.toBase64String(signature), 'base64');
    if (isEcdsaAlgorithm(algorithm)) {
        signatureBuffer = convertJwsSignatureToEcdsa(signatureBuffer, algorithm);
    }
    return pubKey.doVerify(macAlgorithm, keyBuffer, payloadBuffer, signatureBuffer);
};

module.exports = {
    signatureAlgorithm: signatureAlgorithm,
    createHmac : createHmac,
    validateHmac : validateHmac,
    createSignature : createSignature,
    validateSignature : validateSignature
};
