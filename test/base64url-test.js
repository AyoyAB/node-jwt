var expect = require('chai').expect;
var base64url = require('../lib/base64url');

describe('base64url', function() {
    // NB: Test data is from RFC 4648.
    var base64Alphabet    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var base64urlAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    describe('.toBase64String()', function() {
        it('should not pad the empty string', function () {
            var res = base64url.toBase64String('');

            expect(res.length).to.equal(0);
        });

        it('should pad two character strings with two characters', function () {
            var res = base64url.toBase64String('Zg');

            expect(res.length).to.equal(4);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('g');
            expect(res[2]).to.equal('=');
            expect(res[3]).to.equal('=');
        });

        it('should pad three character strings with one character', function () {
            var res = base64url.toBase64String('Zm8');

            expect(res.length).to.equal(4);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('8');
            expect(res[3]).to.equal('=');
        });

        it('should not pad four character strings', function () {
            var res = base64url.toBase64String('Zm9v');

            expect(res.length).to.equal(4);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
        });

        it('should pad six character strings with two characters', function () {
            var res = base64url.toBase64String('Zm9vYg');

            expect(res.length).to.equal(8);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('g');
            expect(res[6]).to.equal('=');
            expect(res[7]).to.equal('=');
        });

        it('should pad seven character strings with one character', function () {
            var res = base64url.toBase64String('Zm9vYmE');

            expect(res.length).to.equal(8);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('m');
            expect(res[6]).to.equal('E');
            expect(res[7]).to.equal('=');
        });

        it('should not pad eight character strings', function () {
            var res = base64url.toBase64String('Zm9vYmFy');

            expect(res.length).to.equal(8);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('m');
            expect(res[6]).to.equal('F');
            expect(res[7]).to.equal('y');
        });

        it('should correctly translate base64url alphabet to base64', function () {
            var res = base64url.toBase64String(base64urlAlphabet);

            expect(res).to.equal(base64Alphabet);
        });
    });

    describe('.fromBase64String()', function() {
        it("should handle the empty string", function() {
            var res = base64url.fromBase64String('');

            expect(res.length).to.equal(0);
        });

        it("should remove two padding characters from a two character string", function() {
            var res = base64url.fromBase64String('Zg==');

            expect(res.length).to.equal(2);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('g');
        });

        it("should remove one padding character from a three character string", function() {
            var res = base64url.fromBase64String('Zm8=');

            expect(res.length).to.equal(3);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('8');
        });

        it("should remove nothing from a four character string", function() {
            var res = base64url.fromBase64String('Zm9v');

            expect(res.length).to.equal(4);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
        });

        it("should remove two padding characters from a six character string", function() {
            var res = base64url.fromBase64String('Zm9vYg==');

            expect(res.length).to.equal(6);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('g');
        });

        it("should remove one padding character from a seven character string", function() {
            var res = base64url.fromBase64String('Zm9vYmE=');

            expect(res.length).to.equal(7);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('m');
            expect(res[6]).to.equal('E');
        });

        it("should remove nothing from an eight character string", function() {
            var res = base64url.fromBase64String('Zm9vYmFy');

            expect(res.length).to.equal(8);
            expect(res[0]).to.equal('Z');
            expect(res[1]).to.equal('m');
            expect(res[2]).to.equal('9');
            expect(res[3]).to.equal('v');
            expect(res[4]).to.equal('Y');
            expect(res[5]).to.equal('m');
            expect(res[6]).to.equal('F');
            expect(res[7]).to.equal('y');
        });

        it('should correctly translate base64 alphabet to base64url', function () {
            var res = base64url.fromBase64String(base64Alphabet);

            expect(res).to.equal(base64urlAlphabet);
        });
    });
});
