(function(expect, Hmac) {
    'use strict';

    describe('HMAC: ctor', function() {
        var hmac;

        beforeEach(function() {
            hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
        });

        it('should set public and private keys', function() {
            expect(hmac.publicKey).to.equal(PUBLIC_KEY);
            expect(hmac.privateKey).to.equal(PRIVATE_KEY);
        });
    });

})(expect, Hmac);
