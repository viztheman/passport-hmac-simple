(function(expect, Hmac, $) {
    'use strict';

    describe('HMAC: GET', function() {
        var hmac;

        beforeEach(function() {
            hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
        });

        describe('#sendQueryReturnTimestamp', function() {
            var ajaxStub;

            beforeEach(function() {
                ajaxStub = sinon.stub(window, 'fetch');
            });

            afterEach(function() {
                ajaxStub.restore();
            });

            it('should send GET query successfully', function() {
                var success = sinon.fake();
                var error = sinon.fake();
                ajaxStub.resolves({json: sinon.fake()});

                var timestamp = hmac.sendQueryReturnTimestamp('GET', TEST_URL, success, error);
                
                expect(ajaxStub).to.be.calledWithMatch(
                    stampUrl(TEST_URL, timestamp),
                    { method: 'GET' }
                );

                var options = ajaxStub.args[0][1];
                expect(options).to.be.ok.and.include.keys('headers');
                expect(options.headers).to.have.property('Authorization');
            });

            it('should call success on success', function(done) {
                ajaxStub.resolves({json: sinon.fake()});

                hmac.sendQueryReturnTimestamp(
                    'GET',
                    TEST_URL,
                    done,
                    function(e) {
                        console.log(e.message);
                        expect.fail('should have been successful');
                    }
                );
            });

            it('should call error on error', function(done) {
                ajaxStub.rejects();
                /*ajaxStub.returns(new Promise(function(res, rej) {
                    rej('boom');
                }));*/

                hmac.sendQueryReturnTimestamp(
                    'GET',
                    TEST_URL,
                    function() { expect.fail('should have errored'); },
                    function() { done(); }
                );
            });
        });

        describe('macro functions', function() {
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
    });

})(expect, Hmac, jQuery);
