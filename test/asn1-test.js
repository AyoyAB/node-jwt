var expect = require('chai').expect;
var asn1 = require('../lib/asn1');

describe('asn1', function() {
    var TEST_P256_KEY_DATA = {
        algorithm: asn1.algorithm['id-ecPublicKey'],
        curve: asn1.namedCurve['P-256'],
        d:  new Buffer ([
            0x06, 0x8b, 0x3a, 0xcf, 0x8e, 0x46, 0x6d, 0xb7, 0x48, 0x53, 0x6f, 0x06, 0x10, 0x38, 0xca, 0xf1,
            0x9a, 0xfe, 0xac, 0x09, 0xe6, 0x58, 0x52, 0x1d, 0x03, 0xce, 0x2f, 0x8f, 0x54, 0x43, 0x53, 0x86
        ]),
        x: new Buffer ([
            0x0e, 0xf9, 0x71, 0x48, 0x81, 0xce, 0xb8, 0xf4, 0xe4, 0x79, 0xaa, 0x53, 0x5f, 0x63, 0x31, 0x33,
            0x78, 0xc8, 0xd5, 0x57, 0xe6, 0x9d, 0x2e, 0x55, 0xd5, 0xdf, 0x34, 0xf9, 0xf3, 0xcf, 0x40, 0x6c
        ]),
        y: new Buffer ([
            0x90, 0xa7, 0xf9, 0xa1, 0xfb, 0xf1, 0x95, 0x09, 0xb3, 0xe7, 0xe9, 0xe5, 0x6f, 0x2a, 0x5e, 0x59,
            0xbb, 0x8c, 0x3f, 0x9c, 0x86, 0x28, 0x62, 0x83, 0x9f, 0xa4, 0xb3, 0x5d, 0x26, 0x90, 0xd2, 0x00
        ])
    }, TEST_P256_PRIVATE_KEY_ENCODING = Buffer.concat([
        new Buffer([ 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20 ]),
        TEST_P256_KEY_DATA.d,
        new Buffer([ 0xa0, 0x0a ]),
        TEST_P256_KEY_DATA.curve,
        new Buffer([ 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04 ]),
        TEST_P256_KEY_DATA.x,
        TEST_P256_KEY_DATA.y
    ]), TEST_P256_PUBLIC_KEY_ENCODING = Buffer.concat([
        new Buffer([ 0x30, 0x59, 0x30, 0x13 ]),
        TEST_P256_KEY_DATA.algorithm,
        TEST_P256_KEY_DATA.curve,
        new Buffer([ 0x03, 0x42, 0x00, 0x04 ]),
        TEST_P256_KEY_DATA.x,
        TEST_P256_KEY_DATA.y
    ]);

    describe('.encodeLengthBytes()', function() {
        it('should throw an error if a negative value is passed', function () {
            expect(function () { asn1.encodeLengthBytes(-1); }).to.throw('Negative lengths not supported');
        });
        it('should encode 0 length using short form', function() {
            var res = asn1.encodeLengthBytes(0);
            expect(res.equals(new Buffer([ 0 ]))).to.equal(true);
        });
        it('should encode 0x7f length using short form', function() {
            var res = asn1.encodeLengthBytes(0x7f);
            expect(res.equals(new Buffer([ 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0x80);
            expect(res.equals(new Buffer([ 0x81, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0xff);
            expect(res.equals(new Buffer([ 0x81, 0xff ]))).to.equal(true);
        });
        it('should encode 0x100 length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0x100);
            expect(res.equals(new Buffer([ 0x82, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffff);
            expect(res.equals(new Buffer([ 0x82, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x10000 length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0x10000);
            expect(res.equals(new Buffer([ 0x83, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffff);
            expect(res.equals(new Buffer([ 0x83, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x1000000 length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0x1000000);
            expect(res.equals(new Buffer([ 0x84, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffffff length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffffff);
            expect(res.equals(new Buffer([ 0x84, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should throw an error if a > 32-bit value is passed', function () {
            expect(function () { asn1.encodeLengthBytes(0xffffffff + 1); }).to.throw('Lengths > 0xffffffff not supported');
        });
    });
    describe('.encodeBitString()', function() {
        it('should throw an error if a negative unusedBits is passed', function () {
            expect(function () { asn1.encodeBitString(new Buffer(0), -1); }).to.throw('unusedBits must be between 0 and 7');
        });
        it('should throw an error if a >7 unusedBits is passed', function () {
            expect(function () { asn1.encodeBitString(new Buffer(0), 8); }).to.throw('unusedBits must be between 0 and 7');
        });
        it('should correctly encode a 1-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 7);
            expect(res.equals(new Buffer([ 0x03, 0x02, 0x07, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode a 7-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 1);
            expect(res.equals(new Buffer([ 0x03, 0x02, 0x01, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 8-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 0);
            expect(res.equals(new Buffer([ 0x03, 0x02, 0x00, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(res.equals(new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(res.equals(new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 15-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 1);
            expect(res.equals(new Buffer([ 0x03, 0x03, 0x01, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 16-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 0);
            expect(res.equals(new Buffer([ 0x03, 0x03, 0x00, 0xf0, 0x00 ]))).to.equal(true);
        });
    });
    describe('.encodeContextSpecificValue()', function() {
        it('should throw an error if a negative tag is passed', function () {
            expect(function () { asn1.encodeContextSpecificValue(new Buffer(0), -1); }).to.throw('tag must be between 0 and 31');
        });
        it('should throw an error if a tag > 31 is passed', function () {
            expect(function () { asn1.encodeContextSpecificValue(new Buffer(0), 32); }).to.throw('tag must be between 0 and 31');
        });
        it('should correctly encode a single byte bit string', function () {
            var res = asn1.encodeContextSpecificValue(new Buffer([ 0x03, 0x02, 0x00, 0x01 ]), 0);
            expect(res.equals(new Buffer([ 0xa0, 0x04, 0x03, 0x02, 0x00, 0x01 ]))).to.equal(true);
        });
        it('should correctly encode a two byte bit string', function () {
            var res = asn1.encodeContextSpecificValue(new Buffer([ 0x03, 0x03, 0x00, 0x00, 0x01 ]), 1);
            expect(res.equals(new Buffer([ 0xa1, 0x05, 0x03, 0x03, 0x00, 0x00, 0x01 ]))).to.equal(true);
        });
    });
    describe('encodeSubjectPublicKey', function () {
        it('should throw an error if a null coordinate is passed', function () {
            expect(function () { asn1.encodeSubjectPublicKey(new Buffer(0), null); }).to.throw('Both x and y coordinates need to be specified');
            expect(function () { asn1.encodeSubjectPublicKey(null, new Buffer(0)); }).to.throw('Both x and y coordinates need to be specified');
        });
        it('should throw an error if an empty coordinate is passed', function () {
            expect(function () { asn1.encodeSubjectPublicKey(new Buffer(0), new Buffer([ 0x01 ])); }).to.throw('Input buffers can not be empty');
            expect(function () { asn1.encodeSubjectPublicKey(new Buffer([ 0x01 ]), new Buffer(0)); }).to.throw('Input buffers can not be empty');
        });
        it('should correctly encode a trivial two-byte public ECC key', function() {
            var res = asn1.encodeSubjectPublicKey(new Buffer([ 0x01 ]), new Buffer([ 0x02 ]));
            expect(res.equals(new Buffer([ 0x03, 0x04, 0x00, 0x04, 0x01, 0x02 ]))).to.equal(true);
        });
        it('should correctly encode a trivial four-byte public ECC key', function() {
            var res = asn1.encodeSubjectPublicKey(new Buffer([ 0x01, 0x02 ]), new Buffer([ 0x03, 0x04 ]));
            expect(res.equals(new Buffer([ 0x03, 0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 ]))).to.equal(true);
        });
    });
    describe('.encodeInteger()', function () {
        it('should throw an error if a negative number is passed', function() {
            expect(function () { asn1.encodeInteger(-1); }).to.throw('Input must be between 0 and 2^32');
        });
        it('should throw an error if a number > 2^32 is passed', function() {
            expect(function () { asn1.encodeInteger(0xffffffff + 1); }).to.throw('Input must be between 0 and 2^32');
        });
        it('should encode zero correctly', function () {
            var res = asn1.encodeInteger(0);
            expect(res.equals(new Buffer([ 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode one correctly', function () {
            var res = asn1.encodeInteger(1);
            expect(res.equals(new Buffer([ 0x02, 0x01, 0x01 ]))).to.equal(true);
        });
        it('should encode 0x7f correctly', function () {
            var res = asn1.encodeInteger(0x7f);
            expect(res.equals(new Buffer([ 0x02, 0x01, 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 correctly', function () {
            var res = asn1.encodeInteger(0x80);
            expect(res.equals(new Buffer([ 0x02, 0x02, 0x00, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff correctly', function () {
            var res = asn1.encodeInteger(0xff);
            expect(res.equals(new Buffer([ 0x02, 0x02, 0x00, 0xff ]))).to.equal(true);
        });
        it('should encode 0x0100 correctly', function () {
            var res = asn1.encodeInteger(0x0100);
            expect(res.equals(new Buffer([ 0x02, 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fff correctly', function () {
            var res = asn1.encodeInteger(0x7fff);
            expect(res.equals(new Buffer([ 0x02, 0x02, 0x7f, 0xff ]))).to.equal(true);
        });
        it('should encode 0x8000 correctly', function () {
            var res = asn1.encodeInteger(0x8000);
            expect(res.equals(new Buffer([ 0x02, 0x03, 0x00, 0x80, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff correctly', function () {
            var res = asn1.encodeInteger(0xffff);
            expect(res.equals(new Buffer([ 0x02, 0x03, 0x00, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x010000 correctly', function () {
            var res = asn1.encodeInteger(0x010000);
            expect(res.equals(new Buffer([ 0x02, 0x03, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7f0000 correctly', function () {
            var res = asn1.encodeInteger(0x7f0000);
            expect(res.equals(new Buffer([ 0x02, 0x03, 0x7f, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x800000 correctly', function () {
            var res = asn1.encodeInteger(0x800000);
            expect(res.equals(new Buffer([ 0x02, 0x04, 0x00, 0x80, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffff);
            expect(res.equals(new Buffer([ 0x02, 0x04, 0x00, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x01000000 correctly', function () {
            var res = asn1.encodeInteger(0x01000000);
            expect(res.equals(new Buffer([ 0x02, 0x04, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fffffff correctly', function () {
            var res = asn1.encodeInteger(0x7fffffff);
            expect(res.equals(new Buffer([ 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0xffffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffffff);
            expect(res.equals(new Buffer([ 0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
    });
    describe('.encodeECPrivateKey()', function () {
        it('should encode TEST_P256_KEY correctly', function () {
            var res = asn1.encodeECPrivateKey(TEST_P256_KEY_DATA.curve, TEST_P256_KEY_DATA.x, TEST_P256_KEY_DATA.y, TEST_P256_KEY_DATA.d);
            expect(res.equals(TEST_P256_PRIVATE_KEY_ENCODING)).to.equal(true);
        });
    });
    describe('.encodeECSubjectPublicKeyInfo()', function () {
        it('should encode TEST_P256_KEY correctly', function () {
            var res = asn1.encodeECSubjectPublicKeyInfo(TEST_P256_KEY_DATA.curve, TEST_P256_KEY_DATA.x, TEST_P256_KEY_DATA.y);
            expect(res.equals(TEST_P256_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
    });
    describe('.encodeDerEcdsaSignature()', function() {
        it('should encode a dummy signature with two single-byte INTEGERs correctly', function () {
            var res = asn1.encodeEcdsaSignature(new Buffer([ 0 ]), new Buffer([ 1 ]));
            expect(res.equals(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]))).to.equal(true);
        });
        it('should encode a dummy signature with two multi-byte INTEGERs correctly', function () {
            var res = asn1.encodeEcdsaSignature(new Buffer([ 0, 1 ]), new Buffer([ 2, 3 ]));
            expect(res.equals(new Buffer([ 0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03 ]))).to.equal(true);
        });
        it('should not pad negative INTEGERs with leading zeros', function () {
            var res = asn1.encodeEcdsaSignature(new Buffer([ 0x80 ]), new Buffer([ 0x81 ]));
            expect(res.equals(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x81 ]))).to.equal(true);
        });
    });
    describe('.decodeDerObject()', function() {
        it('should throw an error if a null Buffer is passed', function() {
            expect(function () { asn1.decodeDerObject(null); }).to.throw('Input buffer required');
        });
        it('should throw an error if an empty Buffer is passed', function() {
            expect(function () { asn1.decodeDerObject(new Buffer(0)); }).to.throw('Input buffer too short');
        });
        it('should throw an error if a single-byte Buffer is passed', function() {
            expect(function () { asn1.decodeDerObject(new Buffer(1)); }).to.throw('Input buffer too short');
        });
        it('should throw an error if a multi-byte identifier is passed', function() {
            // 0xDF has bits 1-15 set, signaling a multi-byte identifier.
            expect(function () { asn1.decodeDerObject(new Buffer([ 0xDF, 0x20, 0x01, 0x00 ])); }).to.throw('Multi-byte identifiers not supported');
        });
        it('should throw an error if an indefinite length object is passed', function() {
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x80, 0x00 ])); }).to.throw('Indefinite length form not supported');
        });
        it('should throw an error if a > 32 ^ byte object is passed', function() {
            // This buffer claims to contain a 2^32 byte INTEGER.
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00 ])); }).to.throw('Content lengths greater than 2^32 bytes not supported');
        });
        it('should throw an error if the  buffer doesn\'t fit the length bytes', function() {
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x81 ])); }).to.throw('Length of length overflows input buffer');
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x82, 0x01 ])); }).to.throw('Length of length overflows input buffer');
        });
        it('should throw an error if a too small buffer is passed', function() {
            // This buffer claims to contain a 2 byte INTEGER, and only one byte is present.
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x02, 0x00 ])); }).to.throw('Content length overflows input buffer');
            expect(function () { asn1.decodeDerObject(new Buffer([ 0x02, 0x81, 0x80, 0x00 ])); }).to.throw('Content length overflows input buffer');
        });
        it('should correctly decode an ASN.1 NULL', function () {
            var res = asn1.decodeDerObject(new Buffer([ 0x05, 0x00 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.NULL,
                length: 0,
                contents: new Buffer(0),
                byteCount: 2
            }));
        });
        it('should correctly decode a single-byte ASN.1 INTEGER', function () {
            // A zero.
            var res = asn1.decodeDerObject(new Buffer([ 0x02, 0x01, 0x00 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x00 ]),
                byteCount: 3
            }));
        });
        it('should correctly decode a multi-byte ASN.1 INTEGER', function () {
            // 0x100
            var res = asn1.decodeDerObject(new Buffer([ 0x02, 0x02, 0x01, 0x00 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 2,
                contents: new Buffer([ 0x01, 0x00 ]),
                byteCount: 4
            }));
        });
        it('should correctly decode a SEQUENCE of two INTEGERs', function () {
            // 0x100
            var res = asn1.decodeDerObject(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.SEQUENCE,
                length: 6,
                contents: new Buffer([ 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]),
                byteCount: 8
            }));

            var res2 = asn1.decodeDerObject(res.contents);
            expect(JSON.stringify(res2)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x00 ]),
                byteCount: 3
            }));

            var res3 = asn1.decodeDerObject(res.contents, res2.byteCount);
            expect(JSON.stringify(res3)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x01 ]),
                byteCount: 3
            }));
        });
    });
    describe('.decodeSpecificDerObject()', function() {
        it('should throw an error if asked to parse an OCTET STRING as an INTEGER', function () {
            expect(function () { asn1.decodeSpecificDerObject(asn1.identifier.INTEGER, new Buffer([ 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should correctly parse an INTEGER', function () {
            var res = asn1.decodeSpecificDerObject(asn1.identifier.INTEGER, new Buffer([ 0x02, 0x01, 0x00 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x00 ]),
                byteCount: 3
            }));
        });
    });
    describe('.decodeDerSequence()', function() {
        it('should throw an error if asked to parse an OCTET STRING', function () {
            expect(function () { asn1.decodeDerSequence(new Buffer([ 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should correctly parse a SEQUENCE of two INTEGERs', function () {
            var res = asn1.decodeDerSequence(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.SEQUENCE,
                length: 6,
                contents: new Buffer([ 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]),
                byteCount: 8
            }));

            var res2 = asn1.decodeDerObject(res.contents);
            expect(JSON.stringify(res2)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x00 ]),
                byteCount: 3
            }));

            var res3 = asn1.decodeDerObject(res.contents, res2.byteCount);
            expect(JSON.stringify(res3)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x01 ]),
                byteCount: 3
            }));
        });
    });
    describe('.decodeDerInteger()', function() {
        it('should throw an error if asked to parse an OCTET STRING', function () {
            expect(function () { asn1.decodeDerInteger(new Buffer([ 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should correctly parse an INTEGER', function () {
            var res = asn1.decodeDerInteger(new Buffer([ 0x02, 0x01, 0x00 ]));
            expect(JSON.stringify(res)).to.equal(JSON.stringify({
                identifier: asn1.identifier.INTEGER,
                length: 1,
                contents: new Buffer([ 0x00 ]),
                byteCount: 3
            }));
        });
    });
    describe('.decodeDerEcdsaSignature()', function() {
        it('should throw an error if asked to parse an OCTET STRING', function () {
            expect(function () { asn1.decodeDerEcdsaSignature(new Buffer([ 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should throw an error if asked to parse a SEQUENCE containing an OCTET STRING', function () {
            expect(function () { asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x03, 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should throw an error if asked to parse a SEQUENCE containing an INTEGER and an OCTET STRING', function () {
            expect(function () { asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x00, 0x04, 0x01, 0x00 ])); }).to.throw('Unexpected object identifier: 4');
        });
        it('should throw an error if asked to parse a SEQUENCE containing just one INTEGER', function () {
            expect(function () { asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x03, 0x02, 0x01, 0x00 ])); }).to.throw('Input buffer too short');
        });
        it('should correctly parse a SEQUENCE of two single-byte INTEGERs', function () {
            // 0x00 & 0x01
            var res = asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 ]));
            expect(res.r.equals(new Buffer([ 0 ]))).to.equal(true);
            expect(res.s.equals(new Buffer([ 1 ]))).to.equal(true);
        });
        it('should correctly parse a SEQUENCE of two multi-byte INTEGERs', function () {
            // 0x0001 & 0x0203
            var res = asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03 ]));
            expect(res.r.equals(new Buffer([ 0, 1 ]))).to.equal(true);
            expect(res.s.equals(new Buffer([ 2, 3 ]))).to.equal(true);
        });
        it('should correctly parse a SEQUENCE of three single-byte INTEGERs, ignoring the third', function () {
            // 0x00, 0x01 & 0x02
            // TODO: Should this be an error?
            var res = asn1.decodeDerEcdsaSignature(new Buffer([ 0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 ]));
            expect(res.r.equals(new Buffer([ 0 ]))).to.equal(true);
            expect(res.s.equals(new Buffer([ 1 ]))).to.equal(true);
        });
    });
});
