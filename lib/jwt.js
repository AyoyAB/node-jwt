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
 * @param {String}  base64UrlKey    The base64url-encoded key
 *
 * @returns {String} The encoded JSON Web Token
 */
exports.encodeJwt = function(protectedHeader, payload, base64UrlKey) {
    if (!protectedHeader || !protectedHeader.alg) {
        throw new Error('alg parameter must be present in header');
    }

    var jsonHeader = JSON.stringify(protectedHeader);
    var base64UrlHeader = base64url.fromBase64String(new Buffer(jsonHeader).toString('base64'));

    var base64UrlPayload = base64url.fromBase64String(new Buffer(payload).toString('base64'));

    var base64UrlHmac = jws.createHmac(
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
 * @function validateJwt
 *
 * @param {String}  encodedJwt      The encoded JWT to validate
 * @param {String}  base64UrlKey    The base64url-encoded key
 *
 * @returns {Boolean} True if the JSON Web Token is valid
 */
exports.validateJwt = function(encodedJwt, base64UrlKey) {
    var encodedComponents = encodedJwt.split('.');
    if (encodedComponents.length != 3) {
        throw new Error('Invalid JWT');
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

    return jws.validateHmac(header.alg, base64UrlKey, base64UrlHeader, base64UrlPayload, base64UrlHmac);
};
