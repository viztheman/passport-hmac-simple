(function(expect, Hmac, CryptoJS) {
    'use strict';

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

        describe('#sendQuery', function() {
            var ajaxStub;

            beforeEach(function() {
                ajaxStub = sinon.stub($, 'ajax');
            });

            afterEach(function() {
                ajaxStub.restore();
            });

            it('should send GET query successfully', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                var timestamp = hmac.sendQueryReturnTimestamp('GET', TEST_URL, success, error);

                expect(ajaxStub).to.have.been.calledWithMatch({
                    type: 'GET',
                    url: stampUrl(TEST_URL, timestamp),
                    success: success,
                    error: error
                });
                expect(ajaxStub.args.length).to.be.greaterThan(0);
                expect(ajaxStub.args[0].length).to.be.greaterThan(0);

                var options = ajaxStub.args[0][0];
                expect(options).to.be.ok.and.include.keys('headers');
                expect(options.headers).to.include.keys('Authorization');
            });

            it('should call success on success', function() {
                var success = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQueryReturnTimestamp('GET', TEST_URL, success, sinon.fake());
                expect(success).to.have.been.called;
            });

            it('should not call error on success', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQueryReturnTimestamp('GET', TEST_URL, success, error);
                expect(error).to.not.have.been.called;
            });

            it('should call error on error', function() {
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQueryReturnTimestamp('GET', TEST_URL, sinon.fake(), error);
                expect(error).to.have.been.called;
            });

            it('should not call success on error', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQueryReturnTimestamp('GET', TEST_URL, success, error);
                expect(success).to.not.have.been.called;
            });
        });

        describe('#sendBody', function() {
            var ajaxStub;

            beforeEach(function() {
                ajaxStub = sinon.stub($, 'ajax');
            });

            afterEach(function() {
                ajaxStub.restore();
            });

            it('should send POST query successfully', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                var timestamp = hmac.sendBodyReturnTimestamp('POST', TEST_URL, DATA, success, error);

                expect(ajaxStub).to.have.been.calledWithMatch({
                    type: 'POST',
                    url: stampUrl(TEST_URL, timestamp),
                    dataType: 'json',
                    data: JSON.stringify(DATA),
                    success: success,
                    error: error
                });

                expect(ajaxStub.args.length).to.be.greaterThan(0);
                expect(ajaxStub.args[0].length).to.be.greaterThan(0);

                var options = ajaxStub.args[0][0];
                expect(options).to.be.ok.and.include.keys('headers');
                expect(options.headers).to.include.keys('Authorization');
            });

            it('should return timestamp after call', function() {
                var timestamp = hmac.sendBodyReturnTimestamp('POST', TEST_URL, {}, sinon.fake(), sinon.fake());
                expect(timestamp).to.be.ok.and.instanceOf(Date);
            });

            it('should call success on success', function() {
                var success = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendBodyReturnTimestamp('POST', TEST_URL, {}, success, sinon.fake());
                expect(success).to.have.been.called;
            });

            it('should not call error on success', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQueryReturnTimestamp('POST', TEST_URL, {}, success, error);
                expect(error).to.not.have.been.called;
            });

            it('should call error on error', function() {
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQueryReturnTimestamp('POST', TEST_URL, {}, sinon.fake(), error);
                expect(error).to.have.been.called;
            });

            it('should not call success on error', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQueryReturnTimestamp('POST', TEST_URL, {}, success, error);
                expect(success).to.not.have.been.called;
            });
        });

        describe('macro functions', function() {
            describe('sendQueryReturnTimestamp', function() {
                var sendQueryStub;

                beforeEach(function() {
                    sendQueryStub = sinon.stub(hmac, 'sendQueryReturnTimestamp');
                });

                afterEach(function() {
                    sendQueryStub.restore();
                });

                it('should call sendQuery properly on GET', function() {
                    var success = sinon.fake();
                    var error = sinon.fake();
                    hmac.get(TEST_URL, success, error);
                    expect(sendQueryStub).to.have.been.calledWith('GET', TEST_URL, success, error);
                });

                it('should call sendQuery properly on DELETE', function() {
                    var success = sinon.fake();
                    var error = sinon.fake();
                    hmac.delete(TEST_URL, success, error);
                    expect(sendQueryStub).to.have.been.calledWith('DELETE', TEST_URL, success, error);
                });
            });

            describe('sendBodyReturnTimestamp', function() {
                var sendBodyStub;

                beforeEach(function() {
                    sendBodyStub = sinon.stub(hmac, 'sendBodyReturnTimestamp');
                });

                afterEach(function() {
                    sendBodyStub.restore();
                });

                it('should call sendBody properly on POST', function() {
                    var success = sinon.fake();
                    var error = sinon.fake();
                    hmac.post(TEST_URL, DATA, success, error);
                    expect(sendBodyStub).to.have.been.calledWith('POST', TEST_URL, DATA, success, error);
                });

                it('should call sendBody properly on PUT', function() {
                    var success = sinon.fake();
                    var error = sinon.fake();
                    hmac.put(TEST_URL, DATA, success, error);
                    expect(sendBodyStub).to.have.been.calledWith('PUT', TEST_URL, DATA, success, error);
                });

                it('should call sendBody properly on PATCH', function() {
                    var success = sinon.fake();
                    var error = sinon.fake();
                    hmac.patch(TEST_URL, DATA, success, error);
                    expect(sendBodyStub).to.have.been.calledWith('PATCH', TEST_URL, DATA, success, error);
                });
            });
        });
    });

})(expect, Hmac, CryptoJS);
