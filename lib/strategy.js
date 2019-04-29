const passport = require('passport-strategy');
const util = require('util');
const crypto = require('crypto');

function Strategy(options, verify) {
    if (!verify) {
        verify = options;
        options = {};
    }
    if (typeof verify !== 'function')
        throw new TypeError('Verify callback is required.');
    
    passport.Strategy.call(this);
    this.name = 'hmac';
    this.verify = verify;
    this.passReqToCallback = options.passReqToCallback;
}
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.createSig = function(req) {
    let lines = [req.method, req.originalUrl, req.date];

    if (req.method !== 'GET' && req.method !== 'DELETE') {
        lines.push(
            req.headers['content-type'] && req.headers['content-type'].indexOf('json') >= 0
                ? JSON.stringify(req.body)
                : req.body
        );
    }

    return lines.join('\n');
};

Strategy.prototype.createHash = function(req, privateKey) {
    let createSig = this.createSig.bind(this);
    let sig = createSig(this, req);
    let buf = new Buffer(sig, 'utf-8');

    return crypto
        .createHmac('sha1', privateKey)
        .update(buf)
        .digest('hex');
};

Strategy.prototype.authenticate = async function(req, options) {
    options = options || {};

    let login = basicAuth(req);
    if (!login) return this.fail(new Error('Bad authorization header.'));
    let {publicKey, hashbase64} = login;
    let hash = Buffer.from(hashbase64, 'base64').toString();

    let verified = (err, user, privateKey, info) => {
        if (err) return this.error(err);

        let createHash = this.createHash.bind(this);
        if (!user || createHash(req, privateKey) !== hash)
            return this.fail({message: options.badRequestMessage || 'Bad credentials.'});

        this.success(user, info);
    };

    try {
        if (this.passReqToCallback)
            this.verify(req, publicKey, verified);
        else
            this.verify(publicKey, verified);
    }
    catch (e) {
        return this.error(e);
    }
};

module.exports = Strategy;
