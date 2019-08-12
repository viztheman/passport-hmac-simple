const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const TIMESTAMP = Date.parse('1996-02-02 03:04:05 GMT');

const GET_REQ = {
    method: 'GET',
    href: () => '/testing/test?a=1&b=2&timestamp=' + TIMESTAMP.valueOf().toString(),
    headers: {},
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const EXPECTED_GET_SIG = [
    GET_REQ.method,
    '',
    '',
    new Date(parseInt(GET_REQ.query.timestamp)).toUTCString(),
    GET_REQ.href()
].join('\n');

const POST_REQ_BODY_DIGEST = '9e0bf104708effc55357dc36f9426ce7'
const POST_REQ = {
    method: 'POST',
    href: () => '/testing/test?timestamp=' + TIMESTAMP.valueOf().toString(),
    body: {a: 1, b: 2, c: 3},
    headers: {
        'content-type': 'application/json',
        'Content-MD5': POST_REQ_BODY_DIGEST
    },
    query: {timestamp: TIMESTAMP.valueOf().toString()}
};
const EXPECTED_POST_SIG = [
    POST_REQ.method,
    POST_REQ.headers['content-type'],
    POST_REQ_BODY_DIGEST,
    new Date(parseInt(POST_REQ.query.timestamp)).toUTCString(),
    POST_REQ.href()
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
