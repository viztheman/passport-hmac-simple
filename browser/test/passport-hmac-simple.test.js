(function(expect, Hmac) {
    'use strict';

    var PUBLIC_KEY = 'public';
    var PRIVATE_KEY = 'private';

    describe('Hmac', function() {
        describe('#constructor', function() {
            it('should set public and private keys', function() {
                var hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
                expect(hmac.publicKey).to.equal(PUBLIC_KEY);
                expect(hmac.privateKey).to.equal(PRIVATE_KEY);
            });
        });

        describe('#createSig', function() {
            var hmac;

            beforeEach(function(done) {
                hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
                done();
            });

            it('should add timestamp to sig', function() {
                var timestamp = new Date();

                var info = {
                    method: 'GET',
                    timestamp: timestamp,
                    url: '/test?abc=123'
                };

                let actualSig = hmac.createSig(info);
                let timestampQuery = 'timestamp=' + timestamp.valueOf().toString();
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
    });

})(expect, Hmac);
