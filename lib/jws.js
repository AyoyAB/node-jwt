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
            throw new Error('Unsupported algorithm: ' + algorithm);
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

exports.validateJws = function(encodedJws, base64UrlKey) {
    var encodedComponents = encodedJws.split('.');
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
