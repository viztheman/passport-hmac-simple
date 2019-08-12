const chai = require('chai');
const Strategy = require('../lib/strategy');
const passport = require('chai-passport-strategy');
const crypto = require('crypto');

const PUBLIC_KEY = 'cf2be2a2-87c2-43d5-bfba-feec32d92f07';
const PRIVATE_KEY = '167b5582-997e-4314-bb2a-bbb6645dac4f';

const BAD_AUTH_HEADER = 'XXXXXXXX';
const BAD_REQUEST_MSG = 'kaboom';
const BAD_PRIVATE_KEY = 'dc766700-892c-4c26-ac07-e00659304d7d';

const expect = chai.expect;
chai.use(passport);

function amendAuthReq(req) {
    let timestamp = new Date();

    req = Object.assign(req, {
        method: 'GET',
        href: () => '/test/failure?timestamp=' + timestamp.valueOf().toString(),
        query: {}
    });
    req.query.timestamp = timestamp.valueOf().toString();
    req.headers.authorization = createAuthHeader(req);
    return req;
}

function createAuthHeader(req) {
    let sig = [
        req.method,
        '',
        '',
        new Date(req.query.timestamp).toUTCString(),
        req.href()
    ].join('\n');

    let hash = crypto.createHmac('sha1', PRIVATE_KEY).update(sig).digest('hex');
    let base64 = Buffer.from(hash).toString('base64');
    return `hmac ${PUBLIC_KEY}:${base64}`;
}

describe('Strategy', () => {
    describe('authenticate', () => {
        describe('Bad header', () => {
            var msg;

            const strategy = new Strategy((pk, done) => done());

            before(function(done) {
                chai.passport.use(strategy)
                    .fail(function(m) {
                        msg = m;
                        done();
                    })
                    .req(req => req.headers.authorization = BAD_AUTH_HEADER)
                    .authenticate({publicKey: PUBLIC_KEY});
            });

            it('should call this.fail for bad auth header', () => {
                expect(msg).to.be.a.string;
                expect(msg).to.be.ok;
            });
        });

        describe('Failed to find public key', () => {
            var msg;

            const strategy = new Strategy((pk, done) => {
                done(null, false);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .fail(function(m) {
                        msg = m;
                        done();
                    })
                    .req(req => amendAuthReq(req))
                    .authenticate();
            });

            it('should call this.fail for unknown public key', () => {
                expect(msg).to.be.a.string;
                expect(msg).to.be.ok;
            });
        });

        describe('Bad private key', () => {
            var msg;

            const strategy = new Strategy((pk, done) => {
                done(null, {}, BAD_PRIVATE_KEY);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .fail(function(m) {
                        msg = m;
                        done();
                    })
                    .req(req => amendAuthReq(req))
                    .authenticate();
            });

            it('should call this.fail', () => {
                expect(msg).to.be.a.string;
                expect(msg).to.be.ok;
            });
        });

        describe('Uses override message', () => {
            var msg;

            const strategy = new Strategy((pk, done) => {
                done(null, false);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .fail(function(m) {
                        msg = m;
                        done();
                    })
                    .req(req => amendAuthReq(req))
                    .authenticate({badRequestMessage: BAD_REQUEST_MSG});
            });

            it('should call this.fail with custom message', () => {
                expect(msg).to.be.a.string;
                expect(msg).to.equal(BAD_REQUEST_MSG);
            });
        });
    });
});
