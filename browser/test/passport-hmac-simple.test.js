(function(expect, Hmac) {
    'use strict';

    var PUBLIC_KEY = 'public';
    var PRIVATE_KEY = 'private';

    describe('Hmac', function() {
        var hmac;

        beforeEach(function(done) {
            hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
            done();
        });

        describe('#constructor', function() {
            it('should set public and private keys', function() {
                expect(hmac.publicKey).to.equal(PUBLIC_KEY);
                expect(hmac.privateKey).to.equal(PRIVATE_KEY);
            });
        });

        describe('#createSig', function() {
            it('should add timestamp to sig', function() {
                var timestamp = new Date();

                var info = {
                    method: 'GET',
                    timestamp: timestamp,
                    url: '/test?abc=123'
                };

                var actualSig = hmac.createSig(info);
                var timestampQuery = 'timestamp=' + timestamp.valueOf().toString();
                expect(actualSig.indexOf(timestampQuery)).to.be.greaterThan(-1);
            });

            it('should generate GET sig', function() {
                var timestamp = new Date();
                var url = '/test/url';

                var info = {
                    method: 'GET',
                    timestamp: timestamp,
                    url: url
                };

                var expectedSig = [
                    'GET',
                    '',
                    '',
                    timestamp.toUTCString(),
                    url + '?timestamp=' + timestamp.valueOf().toString()
                ].join('\n');

                expect(hmac.createSig(info)).to.equal(expectedSig);
            });

            it('should generate POST sig', function() {
                var timestamp = new Date();
                var url = '/post/test';

                var info = {
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({a:1,b:2}),
                    timestamp: timestamp,
                    url
                };
                
                var expectedSig = [
                    'POST',
                    'application/json',
                    '{"a":1,"b":2}',
                    timestamp.toUTCString(),
                    url + '?timestamp=' + timestamp.valueOf().toString()
                ].join('\n');

                expect(hmac.createSig(info)).to.equal(expectedSig);
            });
        });

        describe('#createAuthHeader', function() {
            var RGX_VALID_AUTH_HEADER = new RegExp('^hmac ' + PUBLIC_KEY + ':');
            var RGX_VALID_HASH = /^[0-9a-fA-F]+$/;

            it('should generate valid signature', function() {
                var header = hmac.createAuthHeader({
                    method: 'GET',
                    timestamp: new Date(),
                    url: '/test'
                });

                expect(header).to.be.ok.and.match(RGX_VALID_AUTH_HEADER);

                var passBase64 = header.split(':')[1];
                var pass = passBase64 ? atob(passBase64) : '';
                expect(pass).to.not.be.empty;
                expect(pass).to.match(RGX_VALID_HASH);
            });
        });

        describe('#sendQuery', function() {
        });
    });

})(expect, Hmac);
