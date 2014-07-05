/**
 * ASN.1 DER encoding/decoding module.
 *
 * @module asn1
 */

/**
 * Enum for known ASN.1 OBJECT IDENTIFIERS.
 * @readonly
 * @enum {Buffer}
 */
exports.objectIdentifier = {
    /** Elliptic curve public key identifier */
    'id-ecPublicKey': new Buffer([ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 ]),
    /** NIST P-256 curve identifier */
    'secp256r1': new Buffer([ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 ]),
    /** NIST P-384 curve identifier */
    'secp384r1': new Buffer([ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 ]),
    /** NIST P-521 curve identifier */
    'secp521r1': new Buffer([ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 ])
};

/**
 * Enum for supported ECC named curves.
 * @readonly
 * @enum {Buffer}
 */
exports.namedCurve = {
    'P-256': exports.objectIdentifier['secp256r1'],
    'secp256r1': exports.objectIdentifier['secp256r1'],
    'P-384': exports.objectIdentifier['secp384r1'],
    'secp384r1': exports.objectIdentifier['secp384r1'],
    'P-521': exports.objectIdentifier['secp521r1'],
    'secp521r1': exports.objectIdentifier['secp521r1']
};

/**
 * Returns the supplied value length as DER encoded length bytes.
 *
 * @function encodeLengthBytes
 *
 * @param {number} valueLength The value length to encode
 *
 * @returns {Buffer} The encoded value length
 */
exports.encodeLengthBytes = function(valueLength) {
    if (valueLength < 0) {
        throw new RangeError('Negative lengths not supported');
    }
    if (valueLength <= 0x7f) {
        // Use short form encoding.
        return new Buffer([ valueLength ]);
    } else if (valueLength <= 0xff) {
        // Use long form encoding.
        return new Buffer([ 0x81, valueLength]);
    } else if (valueLength <= 0xffff) {
        return new Buffer([ 0x82, (valueLength & 0xff00) >> 8, valueLength & 0x00ff ]);
    } else if (valueLength <= 0xffffff) {
        return new Buffer([ 0x83, (valueLength & 0xff0000) >> 16, (valueLength & 0xff00) >> 8, valueLength & 0x00ff ]);
    } else if (valueLength <= 0xffffffff) {
        return new Buffer([ 0x84, (valueLength & 0xff000000) >> 24, (valueLength & 0xff0000) >> 16, (valueLength & 0xff00) >> 8, valueLength & 0x00ff ])
    } else {
        throw new RangeError('Lengths > 0xffffffff not supported');
    }
};

/**
 * Returns the supplied Buffer encoded as a DER encoded BIT STRING.
 *
 * @function encodeBitString
 *
 * @param {Buffer} valueBuffer The buffer containing the BIT STRING to encode
 * @param {number} unusedBits  The number of unused trailing bits in the buffer
 *
 * @returns {Buffer} The encoded ASN.1 BIT STRING
 */
exports.encodeBitString = function(valueBuffer, unusedBits) {
    var TAG = 3, contentBytes, lengthBytes;
    if (unusedBits < 0 || unusedBits > 7) {
        throw new RangeError('unusedBits must be between 0 and 7');
    }

    contentBytes = Buffer.concat([ new Buffer([ unusedBits ]), valueBuffer ]);
    lengthBytes = exports.encodeLengthBytes(contentBytes.length);

    return Buffer.concat([ new Buffer([ TAG ]), lengthBytes, contentBytes ]);
};

/**
 * Returns the supplied Buffer wrapped in a DER encoded content-specific constructed value.
 *
 * @function encodeContentSpecificValue
 *
 * @param {Buffer} valueBuffer The buffer containing the BIT STRING to encode
 * @param {number} tag         The tag number (0-31) to use.
 *
 * @returns {Buffer} The encoded value
 */
exports.encodeContentSpecificValue = function(valueBuffer, tag) {
    var BASE_TAG = 0xa0, lengthBytes;
    if (tag < 0 || tag > 31) {
        throw new RangeError('tag must be between 0 and 31');
    }

    lengthBytes = exports.encodeLengthBytes(valueBuffer.length);
    return Buffer.concat([ new Buffer([ BASE_TAG | tag ]), lengthBytes, valueBuffer ]);
};

/**
 * Returns an uncompressed DER encoded RFC 5480 ECC subjectPublicKey from the specified x and y coordinates.
 *
 * @function encodeSubjectPublicKey
 *
 * @param {Buffer} x The ECC public key x coordinate
 * @param {Buffer} y The ECC public key y coordinate
 *
 * @returns {Buffer} The encoded RFC 5480 subjectPublicKey
 */
exports.encodeSubjectPublicKey = function(x, y) {
    var UNCOMPRESSED_KEY = 4, publicKeyData;
    if (!x || !y) {
        throw new Error('Both x and y coordinates need to be specified');
    }
    if (x.length === 0 || y.length === 0) {
        throw new Error('Input buffers can not be empty');
    }

    publicKeyData = Buffer.concat([ new Buffer([ UNCOMPRESSED_KEY ]), x, y ]);
    return exports.encodeBitString(publicKeyData, 0);
};

/**
 * Returns an uncompressed DER encoded ECC RFC 5915 publicKey from the specified x and y coordinates.
 *
 * @function encodePublicKey
 *
 * @param {Buffer} x The ECC public key x coordinate
 * @param {Buffer} y The ECC public key y coordinate
 *
 * @returns {Buffer} The encoded RFC 5915 publicKey
 */
exports.encodePublicKey = function(x, y) {
    var TAG = 1;

    return exports.encodeContentSpecificValue(exports.encodeSubjectPublicKey(x, y), TAG);
};

/**
 * Returns the supplied Buffer DER encoded as an ASN.1 OBJECT IDENTIFIER.
 *
 * @function encodeObjectIdentifier
 *
 * @param {Buffer} valueBuffer The buffer containing the OBJECT IDENTIFIER to encode
 *
 * @returns {Buffer} The DER encoded ASN.1 OBJECT IDENTIFIER
 */
exports.encodeObjectIdentifier = function(valueBuffer) {
    var TAG = 6;

    return Buffer.concat([
        new Buffer([ TAG ]),
        exports.encodeLengthBytes(valueBuffer.length),
        valueBuffer
    ]);
};

/**
 * Returns an RFC 5915 ECParameters encoding from the named curve.
 *
 * @function encodeECParameters
 *
 * @param {namedCurve} namedCurve The known named curve
 *
 * @returns {Buffer} the DER encoded RFC 5915 ECParameters
 */
exports.encodeECParameters = function(namedCurve) {
    var TAG = 0;

    return exports.encodeContentSpecificValue(namedCurve, TAG);
};

/**
 * Returns the supplied Buffer encoded as a DER encoded OCTET STRING.
 *
 * @function encodeOctetString
 *
 * @param {Buffer} valueBuffer The buffer containing the data to encode
 *
 * @returns {Buffer} The DER encoded ASN.1 OCTET STRING
 */
exports.encodeOctetString = function(valueBuffer) {
    var TAG = 4;

    return Buffer.concat([
        new Buffer([ TAG ]),
        exports.encodeLengthBytes(valueBuffer.length),
        valueBuffer
    ]);
};

/**
 * Returns the input values DER encoded as an ASN.1 SEQUENCE
 *
 * @function encodeSequence
 *
 * @param {Buffer[]} valueBufferArray The array of Buffers containing the encoded values to include
 *
 * @returns {Buffer} The array of inputs DER encoded as an ASN.1 SEQUENCE
 */
exports.encodeSequence = function(valueBufferArray) {
    var TAG = 0x30, contentBytes = Buffer.concat(valueBufferArray);

    return Buffer.concat([
        new Buffer([ TAG ]),
        exports.encodeLengthBytes(contentBytes.length),
        contentBytes
    ]);
};
