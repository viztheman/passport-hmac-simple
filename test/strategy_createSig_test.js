const chai = require('chai');
const expect = chai.expect;
const Strategy = require('../lib/strategy');

const TEST_URL = '/test/items?abc=123';

function createSigBody(req, isJson) {
    let lines = [req.method, req.originalUrl, req.date];

    if (req.body)
        lines.push(isJson ? JSON.stringify(req.body) : req.body);

    return lines.join('\n');
}

describe('Strategy', () => {
    describe('createSig', () => {
        it('should use method, originalUrl, and date on GET', () => {
            let req = {method: 'GET', originalUrl: TEST_URL, date: new Date().toUTCString()};
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(strategy, req);

            let expected = createSigBody(req);
            expect(sig).to.equal(expected);
        });

        it('should use method, originalUrl, and date on DELETE', () => {
            let req = {method: 'DELETE', originalUrl: TEST_URL, date: new Date().toUTCString()};
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(strategy, req);

            let expected = createSigBody(req);
            expect(sig).to.equal(expected);
        });

        it('should use method, originalUrl, date, and urlencoded body on postback', () => {
            let req = {
                method: 'POST',
                originalUrl: TEST_URL,
                date: new Date().toUTCString(),
                body: 'a=1&b=2&c=3',
                headers: {}
            };
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(strategy, req);

            let expected = createSigBody(req);
            expect(sig).to.equal(expected);
        });

        it('should use method, originalUrl, date, and json body on json postback', () => {
            let jsonPayload = {a: 1, b: 2, c: 3};
            let req = {
                method: 'POST',
                originalUrl: TEST_URL,
                date: new Date().toUTCString(),
                body: jsonPayload,
                headers: {'content-type': 'application/json'}
            };
            let strategy = new Strategy(() => {});
            let sig = strategy.createSig.call(strategy, req);

            let expected = createSigBody(req, true);
            expect(sig).to.equal(expected);
        });
    });
});
