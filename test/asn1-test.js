var expect = require('chai').expect;
var asn1 = require('../lib/asn1');
var util = require('./util');

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
            expect(util.bufferEquals(res, new Buffer([ 0 ]))).to.equal(true);
        });
        it('should encode 0x7f length using short form', function() {
            var res = asn1.encodeLengthBytes(0x7f);
            expect(util.bufferEquals(res, new Buffer([ 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0x80);
            expect(util.bufferEquals(res, new Buffer([ 0x81, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0xff);
            expect(util.bufferEquals(res, new Buffer([ 0x81, 0xff ]))).to.equal(true);
        });
        it('should encode 0x100 length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0x100);
            expect(util.bufferEquals(res, new Buffer([ 0x82, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffff);
            expect(util.bufferEquals(res, new Buffer([ 0x82, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x10000 length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0x10000);
            expect(util.bufferEquals(res, new Buffer([ 0x83, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffff);
            expect(util.bufferEquals(res, new Buffer([ 0x83, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x1000000 length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0x1000000);
            expect(util.bufferEquals(res, new Buffer([ 0x84, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffffff length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffffff);
            expect(util.bufferEquals(res, new Buffer([ 0x84, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
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
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x02, 0x07, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode a 7-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 1);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x02, 0x01, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 8-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 0);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x02, 0x00, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 15-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 1);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x03, 0x01, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 16-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 0);
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x03, 0x00, 0xf0, 0x00 ]))).to.equal(true);
        });
    });
    describe('.encodeContentSpecificValue()', function() {
        it('should throw an error if a negative tag is passed', function () {
            expect(function () { asn1.encodeContentSpecificValue(new Buffer(0), -1); }).to.throw('tag must be between 0 and 31');
        });
        it('should throw an error if a tag > 31 is passed', function () {
            expect(function () { asn1.encodeContentSpecificValue(new Buffer(0), 32); }).to.throw('tag must be between 0 and 31');
        });
        it('should correctly encode a single byte bit string', function () {
            var res = asn1.encodeContentSpecificValue(new Buffer([ 0x03, 0x02, 0x00, 0x01 ]), 0);
            expect(util.bufferEquals(res, new Buffer([ 0xa0, 0x04, 0x03, 0x02, 0x00, 0x01 ]))).to.equal(true);
        });
        it('should correctly encode a two byte bit string', function () {
            var res = asn1.encodeContentSpecificValue(new Buffer([ 0x03, 0x03, 0x00, 0x00, 0x01 ]), 1);
            expect(util.bufferEquals(res, new Buffer([ 0xa1, 0x05, 0x03, 0x03, 0x00, 0x00, 0x01 ]))).to.equal(true);
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
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x04, 0x00, 0x04, 0x01, 0x02 ]))).to.equal(true);
        });
        it('should correctly encode a trivial four-byte public ECC key', function() {
            var res = asn1.encodeSubjectPublicKey(new Buffer([ 0x01, 0x02 ]), new Buffer([ 0x03, 0x04 ]));
            expect(util.bufferEquals(res, new Buffer([ 0x03, 0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 ]))).to.equal(true);
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
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode one correctly', function () {
            var res = asn1.encodeInteger(1);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x01, 0x01 ]))).to.equal(true);
        });
        it('should encode 0x7f correctly', function () {
            var res = asn1.encodeInteger(0x7f);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x01, 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 correctly', function () {
            var res = asn1.encodeInteger(0x80);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x02, 0x00, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff correctly', function () {
            var res = asn1.encodeInteger(0xff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x02, 0x00, 0xff ]))).to.equal(true);
        });
        it('should encode 0x0100 correctly', function () {
            var res = asn1.encodeInteger(0x0100);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fff correctly', function () {
            var res = asn1.encodeInteger(0x7fff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x02, 0x7f, 0xff ]))).to.equal(true);
        });
        it('should encode 0x8000 correctly', function () {
            var res = asn1.encodeInteger(0x8000);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x03, 0x00, 0x80, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff correctly', function () {
            var res = asn1.encodeInteger(0xffff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x03, 0x00, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x010000 correctly', function () {
            var res = asn1.encodeInteger(0x010000);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x03, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7f0000 correctly', function () {
            var res = asn1.encodeInteger(0x7f0000);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x03, 0x7f, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x800000 correctly', function () {
            var res = asn1.encodeInteger(0x800000);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x04, 0x00, 0x80, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x04, 0x00, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x01000000 correctly', function () {
            var res = asn1.encodeInteger(0x01000000);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x04, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fffffff correctly', function () {
            var res = asn1.encodeInteger(0x7fffffff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0xffffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffffff);
            expect(util.bufferEquals(res, new Buffer([ 0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
    });
    describe('.encodeECPrivateKey()', function () {
        it('should encode TEST_P256_KEY correctly', function () {
            var res = asn1.encodeECPrivateKey(TEST_P256_KEY_DATA.curve, TEST_P256_KEY_DATA.x, TEST_P256_KEY_DATA.y, TEST_P256_KEY_DATA.d);
            expect(util.bufferEquals(res, TEST_P256_PRIVATE_KEY_ENCODING)).to.equal(true);
        });
    });
    describe('.encodeECSubjectPublicKeyInfo()', function () {
        it('should encode TEST_P256_KEY correctly', function () {
            var res = asn1.encodeECSubjectPublicKeyInfo(TEST_P256_KEY_DATA.curve, TEST_P256_KEY_DATA.x, TEST_P256_KEY_DATA.y);
            expect(util.bufferEquals(res, TEST_P256_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
    });
});
