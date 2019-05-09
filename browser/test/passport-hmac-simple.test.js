(function(expect, Hmac) {
    'use strict';

    var PUBLIC_KEY = 'public';
    var PRIVATE_KEY = 'private';
    var RGX_VALID_HASH = /^[0-9a-fA-F]+$/;

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
                    data: JSON.stringify({a:2,b:2}),
                    timestamp: timestamp,
                    url
                };
                
                var expectedSig = [
                    'POST',
                    'application/json',
                    '{"a":2,"b":2}',
                    timestamp.toUTCString(),
                    url + '?timestamp=' + timestamp.valueOf().toString()
                ].join('\n');

                expect(hmac.createSig(info)).to.equal(expectedSig);
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
                var info = {
                    method: 'GET',
                    timestamp: new Date(),
                    url: '/testing/abc?q=1'
                };
                var sig = [
                    info.method,
                    '',
                    '',
                    info.timestamp.toUTCString(),
                    info.url + '&timestamp=' + info.timestamp.valueOf().toString()
                ].join('\n');

                var actualHash = hmac.createHash(info);
                expect(hmacSha1Spy).to.have.been.calledWith(sig, PRIVATE_KEY);
                expect(actualHash).to.match(RGX_VALID_HASH);
            });

            it('should generate valid hash for POST', function() {
                var info = {
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({x: 'abc', b: 2}),
                    timestamp: new Date(),
                    url: '/postTest'
                };
                var sig = [
                    info.method,
                    info.contentType,
                    info.data,
                    info.timestamp.toUTCString(),
                    info.url + '?timestamp=' + info.timestamp.valueOf().toString()
                ].join('\n');

                var actualHash = hmac.createHash(info);
                expect(hmacSha1Spy).to.have.been.calledWith(sig, PRIVATE_KEY);
                expect(actualHash).to.match(RGX_VALID_HASH);
            });
        });

        describe('#createAuthHeader', function() {
            var RGX_VALID_AUTH_HEADER = new RegExp('^hmac ' + PUBLIC_KEY + ':');

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
                var timestamp = hmac.sendQuery('GET', '/test.aspx', success, error);

                expect(ajaxStub) .to.have.been.calledWithMatch({
                    type: 'GET',
                    url: '/test.aspx?timestamp=' + timestamp.valueOf().toString(),
                    success: success,
                    error: error
                });

                var options = ajaxStub.args[0][0];
                expect(options).to.be.ok.and.include.keys('headers');
                expect(options.headers).to.include.keys('Authorization');
            });

            it('should call success on success', function() {
                var success = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQuery('GET', '/test.aspx', success, sinon.fake());
                expect(success).to.have.been.called;
            });

            it('should not call error on success', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQuery('GET', '/test.aspx', success, error);
                expect(error).to.not.have.been.called;
            });

            it('should call error on error', function() {
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQuery('GET', '/test.aspx', sinon.fake(), error);
                expect(error).to.have.been.called;
            });

            it('should not call success on error', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQuery('GET', '/test.aspx', success, error);
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
                var timestamp = hmac.sendBody('POST', '/test.aspx', {a:1, b:2}, success, error);

                expect(ajaxStub).to.have.been.calledWithMatch({
                    type: 'POST',
                    url: '/test.aspx?timestamp=' + timestamp.valueOf().toString(),
                    dataType: 'json',
                    data: JSON.stringify({a:1, b:2}),
                    success: success,
                    error: error
                });

                var options = ajaxStub.args[0][0];
                expect(options).to.be.ok.and.include.keys('headers');
                expect(options.headers).to.include.keys('Authorization');
            });

            it('should return timestamp after call', function() {
                var timestamp = hmac.sendBody('POST', '/test.aspx', {}, sinon.fake(), sinon.fake());
                expect(timestamp).to.be.ok.and.instanceOf(Date);
            });

            it('should call success on success', function() {
                var success = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendBody('POST', '/test.aspx', {}, success, sinon.fake());
                expect(success).to.have.been.called;
            });

            it('should not call error on success', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { success(); });

                hmac.sendQuery('POST', '/test.aspx', {}, success, error);
                expect(error).to.not.have.been.called;
            });

            it('should call error on error', function() {
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQuery('POST', '/test.aspx', {}, sinon.fake(), error);
                expect(error).to.have.been.called;
            });

            it('should not call success on error', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.callsFake(function() { error(); });

                hmac.sendQuery('POST', '/test.aspx', {}, success, error);
                expect(success).to.not.have.been.called;
            });
        });

        describe('macro functions', function() {
            var sendQueryStub, sendBodyStub;

            beforeEach(function() {
                sendQueryStub = sinon.stub(hmac, 'sendQuery');
                sendBodyStub = sinon.stub(hmac, 'sendBody');
            });

            afterEach(function() {
                sendQueryStub.restore();
                sendBodyStub.restore();
            });

            it('should call sendQuery properly on GET', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                hmac.get('/test', success, error);
                expect(sendQueryStub).to.have.been.calledWith('GET', '/test', success, error);
            });

            it('should call sendBody properly on POST', function() {
                var data = {a:1};
                var success = sinon.fake();
                var error = sinon.fake();
                hmac.post('/test', data, success, error);
                expect(sendBodyStub).to.have.been.calledWith('POST', '/test', data, success, error);
            });

            it('should call sendBody properly on PUT', function() {
                var data = {a:1};
                var success = sinon.fake();
                var error = sinon.fake();
                hmac.put('/test', data, success, error);
                expect(sendBodyStub).to.have.been.calledWith('PUT', '/test', data, success, error);
            });

            it('should call sendBody properly on PATCH', function() {
                var data = {a:1};
                var success = sinon.fake();
                var error = sinon.fake();
                hmac.patch('/test', data, success, error);
                expect(sendBodyStub).to.have.been.calledWith('PATCH', '/test', data, success, error);
            });

            it('should call sendQuery properly on DELETE', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                hmac.delete('/test', success, error);
                expect(sendQueryStub).to.have.been.calledWith('DELETE', '/test', success, error);
            });
        });
    });

})(expect, Hmac);
