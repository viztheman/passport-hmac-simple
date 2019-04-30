const chai = require('chai');
const passport = require('chai-passport-strategy');
const Strategy = require('../lib/strategy');

const ERROR_TEXT = 'boom';
const AUTH_HEADER = 'restify-todo 0705d5a2-faef-4302-b257-8dc9bf5227a9:YTk0YThmZTVjY2IxOWJhNjFjNGMwODczZDM5MWU5ODc5O';

const expect = chai.expect;
chai.use(passport);

describe('Strategy', () => {
    describe('authenticate', () => {
        describe('Graceful errors', () => {
            var err;

            const strategy = new Strategy(function(pk, done) {
                return done(new Error(ERROR_TEXT));
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .error(function(e) {
                        err = e;
                        done();
                    })
                    .req(req => req.headers.authorization = AUTH_HEADER)
                    .authenticate();
            });

            it('should call this.error', () => {
                expect(err).to.be.an.instanceOf(Error);
                expect(err.message).to.equal(ERROR_TEXT);
            });
        });
        
        describe('Ungraceful error', () => {
            var err;

            const strategy = new Strategy(function(pk, done) {
                throw new Error(ERROR_TEXT);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .error(function(e) {
                        err = e;
                        done();
                    })
                    .req(req => req.headers.authorization = AUTH_HEADER)
                    .authenticate();
            });

            it('should call this.error', () => {
                expect(err).to.be.an.instanceOf(Error);
                expect(err.message).to.equal(ERROR_TEXT);
            });
        });
    });
});
