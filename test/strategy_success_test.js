const chai = require('chai');
const passport = require('chai-passport-strategy');
const Strategy = require('../lib/strategy');
const crypto = require('crypto');

const TEST_USER = {};
const TEST_INFO = {};
const PUBLIC_KEY = '15c55efd-3648-4eb2-9e0d-fe8af47daaf4';
const PRIVATE_KEY = 'e3ce629e-fdc5-4b49-a186-59fbf3f56262';
const METHOD = 'GET';
const ORIGINAL_URL = '/test?abc=1';

const expect = chai.expect;
chai.use(passport);

function createAuthHeader() {
    let date = new Date().toUTCString();
    let sig = `${METHOD}\n${ORIGINAL_URL}\n${date}`;
    let buf = Buffer.from(sig, 'utf-8');
    let hash = crypto.createHmac('sha1', PRIVATE_KEY).update(sig).digest('hex');
    let hash64 = Buffer.from(hash).toString('base64');

    return `hmac ${PUBLIC_KEY}:${hash64}`;
}

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
                                date: new Date().toUTCString(),
                                authorization: createAuthHeader()
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
