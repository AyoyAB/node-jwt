var crypto = require('crypto');

exports.doSign = function(digestAlgorithm, privateKeyBuffer, payloadBuffer) {
    var signer = crypto.createSign(digestAlgorithm);
    signer.update(payloadBuffer);
    return signer.sign(privateKeyBuffer);
};

exports.doVerify = function(digestAlgorithm, publicKeyBuffer, payloadBuffer, signatureBuffer) {
    var verifier = crypto.createVerify(digestAlgorithm);
    verifier.update(payloadBuffer);
    return verifier.verify(publicKeyBuffer, signatureBuffer);
};
