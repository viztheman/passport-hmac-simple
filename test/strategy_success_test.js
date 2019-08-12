const chai = require('chai');
const passport = require('chai-passport-strategy');
const Strategy = require('../lib/strategy');
const crypto = require('crypto');

const PUBLIC_KEY = '15c55efd-3648-4eb2-9e0d-fe8af47daaf4';
const PRIVATE_KEY = 'e3ce629e-fdc5-4b49-a186-59fbf3f56262';
const DATA = {a: 1, b: 2};

const TEST_USER = {};
const TEST_INFO = {};

const expect = chai.expect;
chai.use(passport);

function amendReq(req, data) {
    let timestamp = new Date();
    let originalUrl = '/test/abc?def=1&timestamp=' + timestamp.valueOf().toString();

    let newInfo = {
        method: 'GET',
        href: () => originalUrl,
        query: {}
    };

    if (!data) {
        req = Object.assign(req, {
            method: 'GET',
            href: () => originalUrl,
            query: {}
        });
    }
    else {
        req = Object.assign(req, {
            method: 'POST',
            href: () => originalUrl,
            query: {},
            body: JSON.stringify(DATA),

        });
        req.headers['content-type'] = 'application/json';
        req.headers['Content-MD5'] = crypto.createHash('md5').update(req.body).digest('hex');
    }

    req.query.timestamp = timestamp.valueOf().toString();
    req.headers.authorization = createAuthHeader(req);
    return req;
}

function createAuthHeader(req) {
    let sig = [
        req.method,
        req.headers['content-type'] || '',
        req.headers['Content-MD5'] || '',
        new Date(parseInt(req.query.timestamp)).toUTCString(),
        req.href()
    ].join('\n');

    let buf = Buffer.from(sig, 'utf-8');
    let hash = crypto.createHmac('sha1', PRIVATE_KEY).update(sig).digest('hex');
    let hash64 = Buffer.from(hash).toString('base64');

    return `hmac ${PUBLIC_KEY}:${hash64}`;
}

describe('Strategy', () => {
    describe('authenticate', () => {
        describe('Successful login on GET', () => {
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
                    .req(req => amendReq(req))
                    .authenticate();
            });

            it('should call this.success with user and info', () => {
                expect(user).to.equal(TEST_USER);
                expect(info).to.equal(TEST_INFO);
            });
        });

        describe('Successful login on POST', () => {
            var user, info;

            const strategy = new Strategy(function(pk, done) {
                done(null, TEST_USER, PRIVATE_KEY, TEST_INFO);
            });

            before(function(done) {
                chai.passport.use(strategy)
                    .fail(e => {
                        console.log(e);
                        done(e);
                    })
                    .success((u, i) => {
                        user = u;
                        info = i;
                        done();
                    })
                    .req(req => amendReq(req, DATA))
                    .authenticate();
            });

            it('should call this.success with user and info', () => {
                expect(user).to.equal(TEST_USER);
                expect(info).to.equal(TEST_INFO);
            });
        });
    });
});
