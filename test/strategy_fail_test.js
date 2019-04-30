const chai = require('chai');
const Strategy = require('../lib/strategy');
const passport = require('chai-passport-strategy');

const BAD_AUTH_HEADER = 'XXXXXXXX';
const GOOD_AUTH_HEADER = 'restify-todo IjA3MDVkNWEyLWZhZWYtNDMwMi1iMjU3LThkYzliZjUyMjdhOTpZVGswWVRobVpUVmpZMkl4T1dKaE5qRmpOR013T0RjelpETTVNV1U1T0RjNU9ESm1ZbUprTXc9PSci';
const BAD_REQUEST_MSG = 'kaboom';
const BAD_PRIVATE_KEY = 'dc766700-892c-4c26-ac07-e00659304d7d';

const expect = chai.expect;
chai.use(passport);

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
                    .authenticate();
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
                    .req(req => req.headers.authorization = GOOD_AUTH_HEADER)
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
                    .req(req => req.headers.authorization = GOOD_AUTH_HEADER)
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
                    .req(req => req.headers.authorization = GOOD_AUTH_HEADER)
                    .authenticate({badRequestMessage: BAD_REQUEST_MSG});
            });

            it('should call this.fail with custom message', () => {
                expect(msg).to.be.a.string;
                expect(msg).to.equal(BAD_REQUEST_MSG);
            });
        });
    });
});
