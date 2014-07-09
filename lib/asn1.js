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
 * Enum for supported public key algorithms.
 * @readonly
 * @enum {Buffer}
 */
exports.algorithm = {
    'id-ecPublicKey': exports.objectIdentifier['id-ecPublicKey']
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
 * Enum for supported ASN.1 identifiers.
 * @readonly
 * @enum {number}
 */
exports.identifier = {
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OBJECT_IDENTIFIER: 0x06,
    SEQUENCE: 0x30,
    CONTEXT_SPECIFIC: 0xa0
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
        return new Buffer([ 0x81, valueLength]);
    } else if (valueLength <= 0xffff) {
        return new Buffer([ 0x82, valueLength >> 8 & 0xff, valueLength & 0xff ]);
    } else if (valueLength <= 0xffffff) {
        return new Buffer([ 0x83, valueLength >> 16 & 0xff, valueLength >> 8 & 0xff, valueLength & 0xff ]);
    } else if (valueLength <= 0xffffffff) {
        return new Buffer([ 0x84, valueLength >> 24 & 0xff, valueLength >> 16 & 0xff, valueLength >> 8 & 0xff, valueLength & 0xff ]);
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
    var contentBytes, lengthBytes;
    if (unusedBits < 0 || unusedBits > 7) {
        throw new RangeError('unusedBits must be between 0 and 7');
    }

    contentBytes = Buffer.concat([ new Buffer([ unusedBits ]), valueBuffer ]);
    lengthBytes = exports.encodeLengthBytes(contentBytes.length);

    return Buffer.concat([ new Buffer([ exports.identifier.BIT_STRING ]), lengthBytes, contentBytes ]);
};

/**
 * Returns the supplied Buffer wrapped in a DER encoded content-specific constructed value.
 *
 * @function encodeContextSpecificValue
 *
 * @param {Buffer} valueBuffer The buffer containing the BIT STRING to encode
 * @param {number} tag         The tag number (0-31) to use.
 *
 * @returns {Buffer} The encoded value
 */
exports.encodeContextSpecificValue = function(valueBuffer, tag) {
    var lengthBytes;
    if (tag < 0 || tag > 31) {
        throw new RangeError('tag must be between 0 and 31');
    }

    lengthBytes = exports.encodeLengthBytes(valueBuffer.length);
    return Buffer.concat([ new Buffer([ exports.identifier.CONTEXT_SPECIFIC | tag ]), lengthBytes, valueBuffer ]);
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
 * Returns the supplied Buffer DER encoded as an ASN.1 OBJECT IDENTIFIER.
 *
 * @function encodeObjectIdentifier
 *
 * @param {Buffer} valueBuffer The buffer containing the OBJECT IDENTIFIER to encode
 *
 * @returns {Buffer} The DER encoded ASN.1 OBJECT IDENTIFIER
 */
exports.encodeObjectIdentifier = function(valueBuffer) {
    return Buffer.concat([
        new Buffer([ exports.identifier.OBJECT_IDENTIFIER ]),
        exports.encodeLengthBytes(valueBuffer.length),
        valueBuffer
    ]);
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
    return Buffer.concat([
        new Buffer([ exports.identifier.OCTET_STRING ]),
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
    var contentBytes = Buffer.concat(valueBufferArray);

    return Buffer.concat([
        new Buffer([ exports.identifier.SEQUENCE ]),
        exports.encodeLengthBytes(contentBytes.length),
        contentBytes
    ]);
};

/**
 * Returns the input value encoded as a positive integer.
 *
 * Only integers between 0 and 2^32 are supported.
 *
 * @function encodeInteger
 *
 * @param {number} number the number to encode
 *
 * @returns {Buffer} The input value encoded as a positive integer
 */
exports.encodeInteger = function(number) {
    // TODO: Create overload that accepts a binary buffer instead.
    if (number < 0 || number > 0xffffffff) {
        throw new RangeError('Input must be between 0 and 2^32');
    }

    if (number <= 0x7f) {
        return new Buffer([ exports.identifier.INTEGER, 0x01, number & 0xff ]);
    } else if (number <= 0x7fff) {
        return new Buffer([ exports.identifier.INTEGER, 0x02, number >> 8 & 0xff, number & 0xff ]);
    } else if (number <= 0x7fffff) {
        return new Buffer([ exports.identifier.INTEGER, 0x03, number >> 16 & 0xff, number >> 8 & 0xff, number & 0xff ]);
    } else if (number <= 0x7fffffff) {
        return new Buffer([ exports.identifier.INTEGER, 0x04, number >> 24 & 0xff, number >> 16 & 0xff, number >> 8 & 0xff, number & 0xff]);
    } else {
        return new Buffer([ exports.identifier.INTEGER, 0x05, 0x00, number >> 24 & 0xff, number >> 16 & 0xff, number >> 8 & 0xff, number & 0xff]);
    }
};

/**
 * Returns an RFC 5915 ECPrivateKey encoding from the specified parameters.
 *
 * @function encodeECPrivateKey
 *
 * @param {namedCurve} namedCurve The named curve to use
 *
 * @param {Buffer} xBuffer The raw public key x coordinate buffer
 * @param {Buffer} yBuffer The raw public key y coordinate buffer
 * @param {Buffer} dBuffer The raw private key buffer
 *
 * @returns {Buffer} the DER encoded RFC 5915 ECPrivateKey
 */
exports.encodeECPrivateKey = function(namedCurve, xBuffer, yBuffer, dBuffer) {
    var VERSION = 1, PARAMETERS_TAG = 0, PUBLIC_KEY_TAG = 1;

    return exports.encodeSequence([
        exports.encodeInteger(VERSION),
        exports.encodeOctetString(dBuffer),
        exports.encodeContextSpecificValue(namedCurve, PARAMETERS_TAG),
        exports.encodeContextSpecificValue(exports.encodeSubjectPublicKey(xBuffer, yBuffer), PUBLIC_KEY_TAG)
    ]);
};

/**
 * Returns an AlgorithmIdentifier encoding with the specified values.
 *
 * @function encodeAlgorithmIdentifier
 *
 * @param {namedCurve} algorithm The public key algorithm
 * @param {Buffer} parameters The public key additional parameter
 *
 * @returns {Buffer} the DER encoded AlgorithmIdentifier
 */
exports.encodeAlgorithmIdentifier = function (algorithm, parameters) {
    return exports.encodeSequence([ algorithm, parameters ]);
};

/**
 * Returns an RFC 5480 SubjectPublicKeyInfo encoding from the specified parameters.
 *
 * @function encodeSubjectPublicKeyInfo
 *
 * @param {namedCurve} namedCurve The named curve to use
 * @param {Buffer} xBuffer The raw public key x coordinate buffer
 * @param {Buffer} yBuffer The raw public key y coordinate buffer
 *
 * @returns {Buffer} the DER encoded RFC 5480 SubjectPublicKeyInfo
 */
exports.encodeECSubjectPublicKeyInfo = function (namedCurve, xBuffer, yBuffer) {
    var ALGORITHM = exports.algorithm['id-ecPublicKey'];

    return exports.encodeSequence([
        exports.encodeAlgorithmIdentifier(ALGORITHM, namedCurve),
        exports.encodeSubjectPublicKey(xBuffer, yBuffer)
    ]);
};

/**
 * Parses the DER length bytes in the input Buffer.
 *
 * @param {Buffer} buffer           The Buffer containing the data to parse
 * @param {number} offset           The offset into the Buffer to start at
 * @param {number} lengthOfLength   The number of length bytes to read
 *
 * @returns {Object} the parsed length
 */
function parseLengthBytes(buffer, offset, lengthOfLength) {
    var parsedLength = 0;

    if (lengthOfLength === 0) {
        throw new Error('Indefinite length form not supported')
    }

    if (lengthOfLength > 4) {
        throw new Error('Content lengths greater than 2^32 bytes not supported');
    }

    if (offset + lengthOfLength > buffer.length) {
        throw new Error('Length of length overflows input buffer');
    }

    if (lengthOfLength > 3) {
        parsedLength += buffer[offset + 3] * 0x1000000;
    }
    if (lengthOfLength > 2) {
        parsedLength += buffer[offset + 2] * 0x10000;
    }
    if (lengthOfLength > 1) {
        parsedLength += buffer[offset + 1] * 0x100;
    }
    parsedLength += buffer[offset];

    return parsedLength;
}

/**
 * Parses the DER encoded object in the Buffer.
 *
 * @param {Buffer} buffer                   The Buffer containing the data to parse
 * @param {number} [offset=0]               The offset into the Buffer to start at
 * @param {number} [length=buffer.length]   The number of bytes to read
 *
 * @returns {Object} the parsed Object...
 */
exports.decodeDerObject = function (buffer, offset, length) {
    var identifier, lengthOfLength, lengthOfContents, originalOffset, contentsBuffer;

    if (!buffer) { throw new Error('Input buffer required'); }
    if (!offset) { offset = 0; }
    if (!length) { length = buffer.length; }

    if (length < 2) { throw new Error('Input buffer too short'); }

    originalOffset = offset;
    identifier = buffer[offset];
    offset++;

    if ((identifier & 0x1F) === 0x1F) {
        // This means the object uses a multi-byte identifier, which we don't support.
        throw new Error('Multi-byte identifiers not supported');
    }

    if ((buffer[offset] & 0x80) === 0x80) {
        lengthOfLength = buffer[offset] ^ 0x80;
        offset++;

        lengthOfContents = parseLengthBytes(buffer, offset, lengthOfLength);
        offset += lengthOfLength;
    } else {
        lengthOfContents = buffer[offset];
        offset++;
    }

    if (offset + lengthOfContents > length) {
        throw new Error('Content length overflows input buffer');
    }

    contentsBuffer = new Buffer(lengthOfContents);
    buffer.copy(contentsBuffer, 0, offset, offset + lengthOfContents);
    offset += lengthOfContents;

    // TODO: Create a prototype asn1Object to extend instead.
    return {
        readBytes: offset - originalOffset,
        object: {
            identifier: identifier,
            length: lengthOfContents,
            contents: contentsBuffer
        }
    };
};
