const passport = require('passport-strategy');
const util = require('util');
const crypto = require('crypto');

const RGX_HMAC_AUTH = /^[^ ]+ +([^:]+):([^ ]+) *$/;
const RGX_AUTH_METHOD = /^[^ ]+ +/;
const DRIFT_WINDOW_MINUTES = 1;

function Strategy(options, verify) {
    // Shift parameters if needed
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
    let digest = '';

    if (req.body) {
        digest = crypto
            .createHash('sha1')
            .update(JSON.stringify(req.body))
            .digest('hex');
    }

    return [
        req.method,
        digest ? req.headers.contentType : '',
        digest,
        new Date(parseInt(req.query.timestamp)).toUTCString(),
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

Strategy.prototype.authenticate = function(req, options) {
    const _this = this;
    options = options || {};

    let parsedAuth = RGX_HMAC_AUTH.exec(req.headers.authorization);
    if (!parsedAuth || parsedAuth.length < 3) return this.fail('Bad authorization header.');

    let [type, publicKey, hashBase64] = parsedAuth;
    let hash = Buffer.from(hashBase64, 'base64').toString();

    let verified = function (err, user, privateKey, info) {
        if (err) return _this.error(err);

        if (
            !user
            || !_this.checkDate(req)
            || _this.createHash(req, privateKey).toLowerCase() !== hash.toLowerCase()
        ) {
            return _this.fail(options.badRequestMessage || 'Bad credentials.');
        }

        _this.success(user, info);
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
