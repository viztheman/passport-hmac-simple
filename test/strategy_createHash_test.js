const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const PRIVATE_KEY = '5b1b2c1c-812e-429d-916c-cee953b4a0e5';

const REQ = {
    method: 'GET',
    originalUrl: '/test/url?a=1',
    headers: {date: 'Mon, 29 Apr 2019 20:36:18 GMT'}
};
const EXPECTED_HMAC = 'ce1f7165f74a99ce48727e535852698623daaaad';

describe('Strategy', () => {
    describe('createHash', () => {
        it('should generate expected HMAC', () => {
            let strategy = new Strategy(() => {});
            let hash = strategy.createHash(REQ, PRIVATE_KEY);
            expect(hash).to.equal(EXPECTED_HMAC);
        });
    });
});
