var asn1      = require('./asn1');
var base64url = require('./base64url');

/**
 * JSON Web Key module.
 *
 * @module jwk
 */

/**
 * Converts a symmetric JSON Web Key to OpenSSL format.
 *
 * This isn't strictly speaking OpenSSL format, rather the type we need for crypto.createHmac()
 *
 * @function symmetricKeyToOpenSSL
 *
 * @param {String} keyData The symmetric key data
 *
 * @returns {Buffer} The key in OpenSSL format
 */
function symmetricKeyToOpenSSL(keyData) {
    return new Buffer(base64url.toBase64String(keyData), 'base64');
}

/**
 * Converts a Buffer into OpenSSL PEM format.
 *
 * @function bufferToPem
 *
 * @param {String} header The PEM header
 * @param {Buffer} buffer The buffer to convert
 * @param {String} footer The PEM footer
 *
 * @returns {Buffer} The buffer in OpenSSL format
 */
function bufferToPem(header, buffer, footer) {
    var lines = buffer.toString('base64').match(/\S{1,64}/g);

    return new Buffer(header + lines.join('\n') + footer);
}

/**
 * Converts a Buffer into OpenSSL EC private key PEM format.
 *
 * @function bufferToPemEcPrivateKEy
 *
 * @param {Buffer} key The buffer to convert
 *
 * @returns {Buffer} The buffer in OpenSSL format
 */
function bufferToPemEcPrivateKEy(key) {
    var HEADER = '-----BEGIN EC PRIVATE KEY-----\n',
        FOOTER = '\n-----END EC PRIVATE KEY-----\n';
    return bufferToPem(HEADER, key, FOOTER);
}

/**
 * Converts a Buffer into OpenSSL public key PEM format.
 *
 * @function bufferToPemEcPrivateKEy
 *
 * @param {Buffer} key The buffer to convert
 *
 * @returns {Buffer} The buffer in OpenSSL format
 */
function bufferToPemPublicKey(key) {
    var HEADER = '-----BEGIN PUBLIC KEY-----\n',
        FOOTER = '\n-----END PUBLIC KEY-----\n';
    return bufferToPem(HEADER, key, FOOTER);
}

/**
 * Converts a JSON Web Key to OpenSSL format.
 *
 * @function jwkToOpenSSL
 *
 * @param {Object} jwk The JSON web key
 *
 * @returns {Buffer} The key in OpenSSL format
 */
exports.jwkToOpenSSL = function (jwk) {
    var namedCurve;

    if (!jwk) { throw new Error('jwk can not be null or undefined'); }
    if (!jwk.kty) { throw new Error('Key type (kty) missing'); }
    switch (jwk.kty) {
        case 'oct':
            if (!jwk.k) { throw new Error('Key data (k) missing'); }

            return symmetricKeyToOpenSSL(jwk.k);
        case 'EC':
            if (!jwk.crv) { throw new Error('Curve (crv) missing'); }
            if (!jwk.x) { throw new Error('X coordinate (x) missing'); }
            if (!jwk.y) { throw new Error('Y coordinate (y) missing'); }

            namedCurve = asn1.namedCurve[jwk.crv];
            if (!namedCurve) { throw new Error('Unsupported Curve (crv): ' + jwk.crv); }

            if (!jwk.d) {
                // No private key (d) present. Encode as public key.
                return bufferToPemPublicKey(
                    asn1.encodeECSubjectPublicKeyInfo(
                        namedCurve,
                        new Buffer(base64url.toBase64String(jwk.x), 'base64'),
                        new Buffer(base64url.toBase64String(jwk.y), 'base64')
                    )
                );
            } else {
                // Private key (d) present. Encode as private key.
                return bufferToPemEcPrivateKEy(
                    asn1.encodeECPrivateKey(
                        namedCurve,
                        new Buffer(base64url.toBase64String(jwk.x), 'base64'),
                        new Buffer(base64url.toBase64String(jwk.y), 'base64'),
                        new Buffer(base64url.toBase64String(jwk.d), 'base64')
                    )
                );
            }

            break;
        default:
            throw new Error('Unsupported key type (kty): ' + jwk.kty);
    }
};
