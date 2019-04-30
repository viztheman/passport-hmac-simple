const chai = require('chai');
const passport = require('chai-passport-strategy');
const Strategy = require('../lib/strategy');

const TEST_USER = {};
const TEST_INFO = {};
const PRIVATE_KEY = 'e3ce629e-fdc5-4b49-a186-59fbf3f56262';
const METHOD = 'GET';
const ORIGINAL_URL = '/test?abc=1';
const DATE = 'Thu, 06 Feb 1997 03:04:03 GMT';
const AUTH_HEADER = 'restify-todo 01aaa33b-13d6-4eb4-8174-2e6d0d7b9da3:NzY4ZWVhN2JiYTcyZjVjMjkzNGM2ODFhN2MyMzg1NDI1YTFjMzU1OA==';

const expect = chai.expect;
chai.use(passport);

describe('Strategy', () => {
    describe('authenticate', () => {
        describe('Successful login', () => {
            var user, info;

            const strategy = new Strategy(function(pk, done) {
                done(null, TEST_USER, PRIVATE_KEY, TEST_INFO);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .success((u, i) => {
                        user = u;
                        info = i;
                        done();
                    })
                    .req(req => {
                        Object.assign(req, {
                            method: METHOD,
                            originalUrl: ORIGINAL_URL,
                            headers: {
                                date: DATE,
                                authorization: AUTH_HEADER
                            }
                        });
                    })
                    .authenticate();
            });

            it('should call this.success with user and info', () => {
                expect(user).to.equal(TEST_USER);
                expect(info).to.equal(TEST_INFO);
            });
        });
    });
});
