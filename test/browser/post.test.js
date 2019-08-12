(function(expect, Hmac, $) {
    'use strict';

    describe('HMAC: POST', function() {
        var hmac;

        beforeEach(function() {
            hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
        });

        describe('#sendBodyReturnTimestamp', function() {
            var ajaxStub;

            beforeEach(function() {
                ajaxStub = sinon.stub(window, 'fetch');
            });

            afterEach(function() {
                ajaxStub.restore();
            });

            it('should send POST query successfully', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.resolves({json: sinon.fake()});

                var timestamp = hmac.sendBodyReturnTimestamp('POST', TEST_URL, DATA, success, error);

                expect(ajaxStub).to.have.been.calledWithMatch(
                    stampUrl(TEST_URL, timestamp),
                    {
                        method: 'POST',
                        body: JSON.stringify(DATA)
                    }
                );

                var options = ajaxStub.args[0][1];
                expect(options).to.have.property('headers');
                expect(options.headers).to.have.property('Authorization');
                expect(options.headers).to.have.property('Content-Type');
            });

            it('should return timestamp after call', function() {
                ajaxStub.resolves({json: sinon.fake()});
                var timestamp = hmac.sendBodyReturnTimestamp('POST', TEST_URL, {}, sinon.fake(), sinon.fake());
                expect(timestamp).to.be.ok.and.instanceOf(Date);
            });

            it('should call success on success', function(done) {
                var success = sinon.fake();
                ajaxStub.resolves({json: sinon.fake()});

                hmac.sendBodyReturnTimestamp(
                    'POST',
                    TEST_URL,
                    {},
                    done,
                    function() { expect.fail('should have succeeded'); }
                );
            });

            it('should call error on error', function(done) {
                ajaxStub.rejects();

                hmac.sendBodyReturnTimestamp(
                    'POST',
                    TEST_URL,
                    {}, 
                    function() { expect.fail('should have errored'); },
                    function() { done(); }
                );
            });
        });

        describe('macro functions', function() {
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
        

})(expect, Hmac, jQuery);
