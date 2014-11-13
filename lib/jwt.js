/**
 * JSON Web Token handling module.
 *
 * @module jwt
 */

var base64url = require('./base64url');
var jws       = require('./jws');

/**
 * Encodes a JSON Web Token.
 *
 * @function encodeJwt
 *
 * @param {Object}  protectedHeader The JWS protected header
 * @param {String}  payload         The serialized payload
 * @param {Object}  [key]           The optional JSON Web key
 *
 * @returns {String} The encoded JSON Web Token
 */
exports.encodeJwt = function(protectedHeader, payload, key) {
    if (!protectedHeader || !protectedHeader.alg) {
        throw new Error('alg parameter must be present in header');
    }

    var jsonHeader = JSON.stringify(protectedHeader);
    var base64UrlHeader = base64url.fromBase64String(new Buffer(jsonHeader).toString('base64'));

    var base64UrlPayload = base64url.fromBase64String(new Buffer(payload).toString('base64'));

    var base64UrlSignature;
    if (jws.isHmacAlgorithm(protectedHeader.alg)) {
        base64UrlSignature = jws.createHmac(
            protectedHeader.alg,
            key,
            base64UrlHeader,
            base64UrlPayload
        );
    } else if (jws.isEcdsaAlgorithm(protectedHeader.alg)) {
        base64UrlSignature = jws.createSignature(
            protectedHeader.alg,
            key,
            base64UrlHeader,
            base64UrlPayload
        );
    } else if (protectedHeader.alg === jws.signatureAlgorithm.None) {
        base64UrlSignature = '';
    } else {
        throw new Error('Unknown alg value in token header: ' + protectedHeader.alg);
    }

    return base64UrlHeader + '.' + base64UrlPayload + '.' + base64UrlSignature;
};

/**
 * Validates a JSON Web Token.
 *
 * @function validateJwt
 *
 * @param {String}  encodedJwt  The encoded JWT to validate
 * @param {Object}  [key]       The optional JSON Web Key
 *
 * @returns {Boolean} True if the JSON Web Token is valid
 */
exports.validateJwt = function(encodedJwt, key) {
    var encodedComponents = encodedJwt.split('.');
    if (encodedComponents.length != 3) {
        throw new Error('Invalid JWT');
    }

    var base64UrlHeader = encodedComponents[0];
    var base64UrlPayload = encodedComponents[1];
    var base64UrlSignature = encodedComponents[2];

    var jsonHeader = new Buffer(base64url.toBase64String(base64UrlHeader), 'base64').toString();

    var header;
    try {
        header = JSON.parse(jsonHeader);
    } catch (e) {
        throw new Error('JWS protected header is not valid JSON');
    }

    switch (header.alg) {
        case undefined:
            throw new Error('No alg key present in token header');
        case jws.signatureAlgorithm.None:
            // Plaintext tokens are always valid.
            return true;
        case jws.signatureAlgorithm.HmacWithSha256:
        case jws.signatureAlgorithm.HmacWithSha384:
        case jws.signatureAlgorithm.HmacWithSha512:
            return jws.validateHmac(header.alg, key, base64UrlHeader, base64UrlPayload, base64UrlSignature);
        case jws.signatureAlgorithm.EcdsaP256WithSha256:
        case jws.signatureAlgorithm.EcdsaP384WithSha384:
        case jws.signatureAlgorithm.EcdsaP521WithSha512:
            return jws.validateSignature(header.alg, key, base64UrlHeader, base64UrlPayload, base64UrlSignature);
        default:
            throw new Error('Unknown alg value in token header: ' + header.alg);
    }
};
