const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const TIMESTAMP = Date.parse('2019-05-01 14:00 GMT');
const PRIVATE_KEY = '5b1b2c1c-812e-429d-916c-cee953b4a0e5';


const GET_REQ = {
    method: 'GET',
    originalUrl: '/test/url?a=1&timestamp=' + TIMESTAMP.valueOf().toString(),
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const EXPECTED_GET_HMAC = '36b060029ae0f36751ee689cc06a0a1a13e5573c';


const POST_REQ = {
    method: 'POST',
    originalUrl: '/test/url?timestamp=' + TIMESTAMP.valueOf().toString(),
    headers: {contentType: 'application/json'},
    body: {a: 1, b: 2},
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const EXPECTED_POST_HMAC = 'd47024331b89fec89cc6bdd86f447fcc555a47e8';


describe('Strategy', () => {
    describe('createHash', () => {
        it('should generate expected HMAC for GET', () => {
            let strategy = new Strategy(() => {});
            let hash = strategy.createHash(GET_REQ, PRIVATE_KEY);
            expect(hash).to.equal(EXPECTED_GET_HMAC);
        });

        it('should generate expected HMAC for POST', () => {
            let strategy = new Strategy(() => {});
            let hash = strategy.createHash(POST_REQ, PRIVATE_KEY);
            expect(hash).to.equal(EXPECTED_POST_HMAC);
        });
    });
});
