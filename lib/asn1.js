/**
 * ASN.1 DER encoding/decoding module.
 *
 * @module asn1
 */

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
