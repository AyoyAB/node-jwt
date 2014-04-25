/**
 * Public key signing and validation module.
 *
 * @module pubkey
 */

var crypto = require('crypto');

/**
 * Signs the specified payload using the supplied private key and algorithm.
 *
 * @function doSign
 *
 * @param {String}  algorithm       The algorithm to use
 * @param {Buffer}  keyBuffer       The private key to use
 * @param {Buffer}  payloadBuffer   The payload to sign
 *
 * @returns {Buffer} The generated signature
 */
exports.doSign = function(algorithm, keyBuffer, payloadBuffer) {
    var signer = crypto.createSign(algorithm);
    signer.update(payloadBuffer);
    return signer.sign(keyBuffer);
};

/**
 * Verifies the specified signature against the payload using the supplied public key and algorithm.
 *
 * @function doVerify
 *
 * @param {String}  algorithm       The algorithm to use
 * @param {Buffer}  keyBuffer       The public key to use
 * @param {Buffer}  payloadBuffer   The expected payload
 * @param {Buffer}  signatureBuffer The signature to verify
 *
 * @returns {Boolean} True if the signature could be verified
 */
exports.doVerify = function(algorithm, keyBuffer, payloadBuffer, signatureBuffer) {
    var verifier = crypto.createVerify(algorithm);
    verifier.update(payloadBuffer);
    return verifier.verify(keyBuffer, signatureBuffer);
};
