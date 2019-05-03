const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const TIMESTAMP = Date.parse('1996-02-02 03:04:05 GMT');

const GET_REQ = {
    method: 'GET',
    originalUrl: '/testing/test?a=1&b=2&timestamp=' + TIMESTAMP.valueOf().toString(),
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const EXPECTED_GET_SIG = [
    GET_REQ.method,
    '',
    '',
    new Date(parseInt(GET_REQ.query.timestamp)).toUTCString(),
    GET_REQ.originalUrl
].join('\n');

const POST_REQ = {
    method: 'POST',
    originalUrl: '/testing/test?timestamp=' + TIMESTAMP.valueOf().toString(),
    body: {a: 1, b: 2, c: 3},
    headers: {contentType: 'application/json'},
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const POST_REQ_BODY_DIGEST = 'e7ec4a8f2309bdd4c4c57cb2adfb79c91a293597';
const EXPECTED_POST_SIG = [
    POST_REQ.method,
    POST_REQ.headers.contentType,
    POST_REQ_BODY_DIGEST,
    new Date(parseInt(POST_REQ.query.timestamp)).toUTCString(),
    POST_REQ.originalUrl
].join('\n');

describe('Strategy', () => {
    describe('createSig', () => {
        it('should create the expected GET signature', () => {
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(this, GET_REQ);
            expect(sig).to.equal(EXPECTED_GET_SIG);
        });

        it('should create the expected POST signature', () => {
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(this, POST_REQ);
            expect(sig).to.equal(EXPECTED_POST_SIG);
        });
    });
});
