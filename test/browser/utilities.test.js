(function(expect, Hmac, CryptoJS) {
    'use strict';

    describe('HMAC: Utilities', function() {
        var hmac;

        beforeEach(function(done) {
            hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
            done();
        });

        describe('#createSig', function() {
            it('should add timestamp to sig', function() {
                var timestamp = new Date();

                var actualSig = hmac.createSig({
                    method: 'GET',
                    timestamp: timestamp,
                    url: TEST_URL
                });

                var timestampQuery = 'timestamp=' + timestamp.valueOf().toString();
                expect(actualSig.indexOf(timestampQuery)).to.be.greaterThan(-1);
            });

            it('should generate GET sig', function() {
                var timestamp = new Date();
                var expectedSig = createGetSig(TEST_URL, timestamp);

                var actualSig = hmac.createSig({
                    method: 'GET',
                    timestamp: timestamp,
                    url: TEST_URL
                });

                expect(actualSig).to.equal(expectedSig);
            });

            it('should generate POST sig', function() {
                var timestamp = new Date();
                var expectedSig = createPostSig(TEST_URL, timestamp, DATA);

                var actualSig = hmac.createSig({
                    method: 'POST',
                    url: TEST_URL,
                    timestamp: timestamp,
                    data: DATA,
                    contentType: 'application/json'
                });
                
                expect(actualSig).to.equal(expectedSig);
            });
        });

        describe('#createHash', function() {
            var hmacSha1Spy;

            beforeEach(function() {
                hmacSha1Spy = sinon.spy(CryptoJS, 'HmacSHA1');
            });

            afterEach(function() {
                hmacSha1Spy.restore();
            });

            it('should generate valid hash for GET', function() {
                var timestamp = new Date();
                var expectedSig = createGetSig(TEST_URL, timestamp);

                var actualHash = hmac.createHash({
                    method: 'GET',
                    timestamp: timestamp,
                    url: TEST_URL
                });

                expect(hmacSha1Spy).to.have.been.calledWith(expectedSig, PRIVATE_KEY);
                expect(actualHash).to.match(RGX_VALID_HASH);
            });

            it('should generate valid hash for POST', function() {
                var timestamp = new Date();
                var expectedSig = createPostSig(TEST_URL, timestamp, DATA);

                var actualHash = hmac.createHash({
                    method: 'POST',
                    contentType: 'application/json',
                    data: DATA,
                    timestamp: timestamp,
                    url: TEST_URL
                });

                expect(hmacSha1Spy).to.have.been.calledWith(expectedSig, PRIVATE_KEY);
                expect(actualHash).to.match(RGX_VALID_HASH);
            });
        });

        describe('#createAuthHeader', function() {
            it('should generate valid auth header', function() {
                var header = hmac.createAuthHeader({
                    method: 'GET',
                    timestamp: new Date(),
                    url: TEST_URL
                });

                expect(header).to.be.ok.and.match(RGX_VALID_AUTH_HEADER);
            });

            it('should encode hmac hash', function() {
                var header = hmac.createAuthHeader({
                    method: 'GET',
                    timestamp: new Date(),
                    url: TEST_URL
                });
                expect(header).to.be.ok;

                var tokens = header.split(':');
                expect(tokens.length).to.equal(2);

                var passBase64 = tokens[1];
                var pass = passBase64 ? atob(passBase64) : '';
                expect(pass).to.not.be.empty;
                expect(pass).to.match(RGX_VALID_HASH);
            });
        });
    });

})(expect, Hmac, CryptoJS);
