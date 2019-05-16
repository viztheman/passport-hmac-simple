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
