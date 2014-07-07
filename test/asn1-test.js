var expect = require('chai').expect;
var asn1 = require('../lib/asn1');

function bufferEquals(lhs, rhs) {
    var i;

    if (lhs.length !== rhs.length) { return false; }

    for (i = 0; i < lhs.length; i++) {
        if (lhs[i] !== rhs[i]) { return false; }
    }

    return true;
}

describe('asn1', function() {
    describe('.encodeLengthBytes()', function() {
        it('should throw an error if a negative value is passed', function () {
            expect(function () { asn1.encodeLengthBytes(-1); }).to.throw('Negative lengths not supported');
        });
        it('should encode 0 length using short form', function() {
            var res = asn1.encodeLengthBytes(0);
            expect(bufferEquals(res, new Buffer([ 0 ]))).to.equal(true);
        });
        it('should encode 0x7f length using short form', function() {
            var res = asn1.encodeLengthBytes(0x7f);
            expect(bufferEquals(res, new Buffer([ 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0x80);
            expect(bufferEquals(res, new Buffer([ 0x81, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff length using single-byte long form', function() {
            var res = asn1.encodeLengthBytes(0xff);
            expect(bufferEquals(res, new Buffer([ 0x81, 0xff ]))).to.equal(true);
        });
        it('should encode 0x100 length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0x100);
            expect(bufferEquals(res, new Buffer([ 0x82, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff length using two byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffff);
            expect(bufferEquals(res, new Buffer([ 0x82, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x10000 length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0x10000);
            expect(bufferEquals(res, new Buffer([ 0x83, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff length using three byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffff);
            expect(bufferEquals(res, new Buffer([ 0x83, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x1000000 length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0x1000000);
            expect(bufferEquals(res, new Buffer([ 0x84, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffffff length using four byte long form', function() {
            var res = asn1.encodeLengthBytes(0xffffffff);
            expect(bufferEquals(res, new Buffer([ 0x84, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
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
            expect(bufferEquals(res, new Buffer([ 0x03, 0x02, 0x07, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode a 7-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 1);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x02, 0x01, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 8-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0 ]), 0);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x02, 0x00, 0xf0 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 9-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 7);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x03, 0x07, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 15-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 1);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x03, 0x01, 0xf0, 0x00 ]))).to.equal(true);
        });
        it('should correctly encode an 16-bit string', function () {
            var res = asn1.encodeBitString(new Buffer([ 0xf0, 0x00 ]), 0);
            expect(bufferEquals(res, new Buffer([ 0x03, 0x03, 0x00, 0xf0, 0x00 ]))).to.equal(true);
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
            expect(bufferEquals(res, new Buffer([ 0xa0, 0x04, 0x03, 0x02, 0x00, 0x01 ]))).to.equal(true);
        });
        it('should correctly encode a two byte bit string', function () {
            var res = asn1.encodeContentSpecificValue(new Buffer([ 0x03, 0x03, 0x00, 0x00, 0x01 ]), 1);
            expect(bufferEquals(res, new Buffer([ 0xa1, 0x05, 0x03, 0x03, 0x00, 0x00, 0x01 ]))).to.equal(true);
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
            expect(bufferEquals(res, new Buffer([ 0x03, 0x04, 0x00, 0x04, 0x01, 0x02 ]))).to.equal(true);
        });
        it('should correctly encode a trivial four-byte public ECC key', function() {
            var res = asn1.encodeSubjectPublicKey(new Buffer([ 0x01, 0x02 ]), new Buffer([ 0x03, 0x04 ]));
            expect(bufferEquals(res, new Buffer([ 0x03, 0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 ]))).to.equal(true);
        });
    });
    describe('.encodePublicKey()', function () {
        it('should correctly encode a trivial two-byte public ECC key', function() {
            var res = asn1.encodePublicKey(new Buffer([ 0x01 ]), new Buffer([ 0x02 ]));
            expect(bufferEquals(res, new Buffer([ 0xa1, 0x06, 0x03, 0x04, 0x00, 0x04, 0x01, 0x02 ]))).to.equal(true);
        });
        it('should correctly encode a trivial four-byte public ECC key', function() {
            var res = asn1.encodePublicKey(new Buffer([ 0x01, 0x02 ]), new Buffer([ 0x03, 0x04 ]));
            expect(bufferEquals(res, new Buffer([ 0xa1, 0x08, 0x03, 0x06, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 ]))).to.equal(true);
        });
    });
    describe('.encodeECParameters()', function () {
        it('should correctly encode the known curve P-256', function () {
            var res = asn1.encodeECParameters(asn1.namedCurve['P-256']);
            expect(bufferEquals(res, new Buffer([ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 ]))).to.equal(true);
        });
        it('should correctly encode the known curve P-384', function () {
            var res = asn1.encodeECParameters(asn1.namedCurve['P-384']);
            expect(bufferEquals(res, new Buffer([ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 ]))).to.equal(true);
        });
        it('should correctly encode the known curve P-521', function () {
            var res = asn1.encodeECParameters(asn1.namedCurve['P-521']);
            expect(bufferEquals(res, new Buffer([ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 ]))).to.equal(true);
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
            expect(bufferEquals(res, new Buffer([ 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode one correctly', function () {
            var res = asn1.encodeInteger(1);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x01, 0x01 ]))).to.equal(true);
        });
        it('should encode 0x7f correctly', function () {
            var res = asn1.encodeInteger(0x7f);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x01, 0x7f ]))).to.equal(true);
        });
        it('should encode 0x80 correctly', function () {
            var res = asn1.encodeInteger(0x80);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x02, 0x00, 0x80 ]))).to.equal(true);
        });
        it('should encode 0xff correctly', function () {
            var res = asn1.encodeInteger(0xff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x02, 0x00, 0xff ]))).to.equal(true);
        });
        it('should encode 0x0100 correctly', function () {
            var res = asn1.encodeInteger(0x0100);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x02, 0x01, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fff correctly', function () {
            var res = asn1.encodeInteger(0x7fff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x02, 0x7f, 0xff ]))).to.equal(true);
        });
        it('should encode 0x8000 correctly', function () {
            var res = asn1.encodeInteger(0x8000);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x03, 0x00, 0x80, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffff correctly', function () {
            var res = asn1.encodeInteger(0xffff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x03, 0x00, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x010000 correctly', function () {
            var res = asn1.encodeInteger(0x010000);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x03, 0x01, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7f0000 correctly', function () {
            var res = asn1.encodeInteger(0x7f0000);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x03, 0x7f, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x800000 correctly', function () {
            var res = asn1.encodeInteger(0x800000);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x04, 0x00, 0x80, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0xffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x04, 0x00, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0x01000000 correctly', function () {
            var res = asn1.encodeInteger(0x01000000);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x04, 0x01, 0x00, 0x00, 0x00 ]))).to.equal(true);
        });
        it('should encode 0x7fffffff correctly', function () {
            var res = asn1.encodeInteger(0x7fffffff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
        it('should encode 0xffffffff correctly', function () {
            var res = asn1.encodeInteger(0xffffffff);
            expect(bufferEquals(res, new Buffer([ 0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff ]))).to.equal(true);
        });
    });
});
