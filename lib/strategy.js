const crypto = require('crypto');
const passport = require('passport-strategy');
const util = require('util');

const DRIFT_WINDOW_MINUTES = 1;
const RGX_AUTH_METHOD = /^[^ ]+ +/;
const RGX_HMAC_AUTH = /^([^ ]+) +([^:]+):([^ ]+) *$/;

function Strategy(options, verify) {
    // Shift parameters if optional ones are excluded
    if (!verify) {
        verify = options;
        options = {};
    }
    if (typeof verify !== 'function')
        throw new TypeError('Verify callback is required.');

    
    // call super()
    passport.Strategy.call(this);

    // set up fields
    this.name = 'hmac';
    this.verify = verify;
    this.passReqToCallback = options.passReqToCallback;
}
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.createSig = function(req) {
    let digest = req.headers['Content-MD5'] || '';

    let timestamp = req.query.timestamp
        ? new Date(parseInt(req.query.timestamp)).toUTCString()
        : '';

    return [
        req.method,
        req.headers.contentType || '',
        digest,
        timestamp,
        req.originalUrl
    ].join('\n');
};

Strategy.prototype.createHash = function(req, privateKey) {
    let sig = this.createSig(req);
    let buf = Buffer.from(sig, 'utf-8');

    return crypto
        .createHmac('sha1', privateKey)
        .update(buf)
        .digest('hex');
};

Strategy.prototype.checkDate = function(req) {
    let now = new Date();
    let nowMinutes = now.getMinutes();
    let lower = new Date(now.valueOf()).setMinutes(nowMinutes - DRIFT_WINDOW_MINUTES);
    let upper = new Date(now.valueOf()).setMinutes(nowMinutes + DRIFT_WINDOW_MINUTES);

    let headerDate = new Date(parseInt(req.query.timestamp));
    return lower <= headerDate && headerDate <= upper;
};

Strategy.prototype.parseAuthHeader = function(req) {
    if (!req.headers.authorization) return null;

    let tokens = RGX_HMAC_AUTH.exec(req.headers.authorization);
    if (!tokens || tokens.length < 4) return null;

    return {
        type: tokens[1],
        publicKey: tokens[2],
        hash: Buffer.from(tokens[3], 'base64').toString()
    };
};

Strategy.prototype.authenticate = function(req, options) {
    const _this = this;
    options = options || {};

    let auth = this.parseAuthHeader(req);
    if (!auth) return this.fail('Bad authorization header.');

    let verified = function (err, user, privateKey, info) {
        if (err) return _this.error(err);

        if (
            !user
            || !_this.checkDate(req)
            || _this.createHash(req, privateKey).toLowerCase() !== auth.hash.toLowerCase()
        ) {
            return _this.fail(options.badRequestMessage || 'Bad credentials.');
        }

        _this.success(user, info);
    };

    try {
        if (this.passReqToCallback)
            this.verify(req, auth.publicKey, verified);
        else
            this.verify(auth.publicKey, verified);
    }
    catch (e) {
        return this.error(e);
    }
};

module.exports = Strategy;
