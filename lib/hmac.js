var crypto = require('crypto');

// Performs a HMAC of the specified payload Buffer using the supplied key Buffer with the specified algorithm.
// Returns the digest as a Buffer.
exports.doHmac = function(algorithm, keyBuffer, payloadBuffer) {
    var hmac = crypto.createHmac(algorithm, keyBuffer);
    hmac.update(payloadBuffer);
    return hmac.digest();
};
