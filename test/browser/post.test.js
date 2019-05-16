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
