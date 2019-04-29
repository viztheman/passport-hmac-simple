const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const REQ = {
    method: 'GET',
    originalUrl: '/testing/test?a=1&b=2',
    date: 'Fri, 02 Feb 1996 03:04:05 GMT'
};

const EXPECTED_SIG = [REQ.method, REQ.originalUrl, REQ.date].join('\n');

describe('Strategy', () => {
    describe('createSig', () => {
        it('should create the expected signature', () => {
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(this, REQ);
            expect(sig).to.equal(EXPECTED_SIG);
        });
    });
});
