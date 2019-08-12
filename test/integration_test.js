const restify = require('restify');
const passport = require('passport');
const HmacStrategy = require('../lib/strategy.js');
const expect = require('chai').expect;
const _ = require('underscore');
const CryptoJS = require('crypto-js');

const TEST_PORT = 18493;
const PUBLIC_KEY = '7b95a0d1-73f7-4d13-b7c3-19ce40394354';
const PRIVATE_KEY = '6923e04f-a5bf-401a-ac0e-62b51d62b771';
const DATA = {a: 123, b: 'xyz'};

function setUpClient() {
    global.CryptoJS = require('crypto-js');
    global.btoa = require('btoa');
    global.Hmac = require('../lib/Hmac.js');
    global.fetch = require('node-fetch');
}

function setUpPassport() {
    passport.use(new HmacStrategy(function(publicKey, done) {
        done(null, {success: publicKey === PUBLIC_KEY}, PRIVATE_KEY);
    }));
}

function sendSuccess(req, res, next) {
    let success = req.user && req.user.success;
    res.json({success});
    next();
}

function createServer() {
    let server = restify.createServer();
    server.use(restify.plugins.queryParser());
    server.use(restify.plugins.bodyParser());
    server.use(passport.initialize());
    server.get('/get', passport.authenticate('hmac', {session:false}), sendSuccess);
    server.post('/post', passport.authenticate('hmac', {session:false}), sendSuccess);
    server.put('/put', passport.authenticate('hmac', {session:false}), sendSuccess);
    server.patch('/patch', passport.authenticate('hmac', {session:false}), sendSuccess);
    server.del('/delete', passport.authenticate('hmac', {session:false}), sendSuccess);

    server.on('Unauthorized', (req, res, err, callback) => {
        res.send({success: false});
        callback();
    });

    return server;
}

function expectRunSuccess(data, done) {
    expect(data).to.have.property('success', true);
    done();
}

function failFromError(done) {
    expect.fail('Should not have called error()');
    done();
}

function runClientTest(client, methodName, data, done) {
    if (!done) {
        done = data;
        data = null;
    }
    let method = client[methodName];

    let methodArgs = [
        `http://localhost:${TEST_PORT}/${methodName}`,
        data,
        data => expectRunSuccess(data, done),
        () => failFromError(done)
    ];
    if (!data) methodArgs.splice(1, 1);

    method.apply(client, methodArgs);
}

describe('Integration Tests', function() {
    var client, server;
    
    before(function() {
        this.timeout(30000);
        setUpPassport();
        setUpClient();
    });

    beforeEach(function(done) {
        client = new Hmac(PUBLIC_KEY, PRIVATE_KEY);
        server = createServer();
        server.listen(TEST_PORT, done);
    });

    afterEach(function() {
        server.close();
    });

    it('should pass GET', function(done) {
        runClientTest(client, 'get', done);
    });

    it('should pass POST', function(done) {
        runClientTest(client, 'post', DATA, done);
    });

    it('should pass PUT', function(done) {
        runClientTest(client, 'put', DATA, done);
    });

    it('should pass PATCH', function(done) {
        runClientTest(client, 'patch', DATA, done);
    });

    it('should pass DELETE', function(done) {
        runClientTest(client, 'delete', done);
    });
});
