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
});
