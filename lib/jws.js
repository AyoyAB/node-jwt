var hmac      = require('./hmac');
var base64url = require('./base64url');

exports.Algorithms = {
    HmacWithSha256: 'HS256',
    RsaSsaWithSha256: 'RS256',
    EcdsaP256WithSha256: 'ES256'
};

var getMacAlgorithm = function(algorithm) {
    switch (algorithm) {
        case exports.Algorithms.HmacWithSha256:
            return "sha256";
        default:
            throw new Error('Unsupported algorithm: ' + algorithm)
    }
};

exports.createHmac = function(algorithm, key, protectedHeader, payload) {
    var macAlgorithm = getMacAlgorithm(algorithm);
    var keyBuffer = new Buffer(base64url.toBase64String(key), 'base64');
    var payloadBuffer = new Buffer(protectedHeader + '.' + payload, 'binary');
    return base64url.fromBase64String(hmac.doHmac(macAlgorithm, keyBuffer, payloadBuffer).toString('base64'));
};

exports.validateHmac = function(algorithm, key, protectedHeader, payload, expectedHmac) {
    var actualHmac =  exports.createHmac(algorithm, key, protectedHeader, payload);

    return actualHmac === expectedHmac;
};
