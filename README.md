# passport-hmac-simple
Simple HMAC authentication for [Passport](https://passportjs.org) and [Node.js](https://nodejs.org).

Server side works like any other Passport strategy: Look up the private key (and optionally user model) associated with the public key, then pass them back as `done(null, user, privateKey)`.

Client side requires a bit more finagling. You'll have to set the Date and Authorization headers properly, but after that, you're good to go.

## Hash Functions
Signatures are generated according to the following pseudocode:

```
InfoToSign = Method + "\n" +
    Full URL + "\n" +
    UTC Date

HMAC = HMAC-SHA1(InfoToSign, PrivateKey, UTF-8) To Hex
base64HMAC = base64(HMAC)
Authorization Header = "hmac PublicKey:base64HMAC"
```

`Full URL` includes query strings but _not_ schema, i.e. `/test?abc=1`. UTC Date is generated by `new Date().toUTCString()`. Here's a working example:

```
InfoToSign = "GET\n/test?abc=1&d=4\nTue, 30 Apr 2019 17:21:45 GMT"

HMAC = HMAC-SHA1(InfoToSign, "This is the private key", utf-8) To Hex
     = db10957f6f5e301be53a0267483f85d016a64324

base64HMAC = ZGIxMDk1N2Y2ZjVlMzAxYmU1M2EwMjY3NDgzZjg1ZDAxNmE2NDMyNA==
Authorization Header = "hmac MyPublicKey:ZGIxMDk1N2Y2ZjVlMzAxYmU1M2EwMjY3NDgzZjg1ZDAxNmE2NDMyNA=="
```

InfoToSign doesn't have a lot of data points, but it _is_ called passport-hmac-_simple_. :) It should still be secure enough for most usages.

Some notes on the values being passed in:

    * Keys can be whatever you want, though random generation (i.e. GUIDs) is _strongly_ encouraged.
    * The Date header _is_ checked server side. One minute of drift in either direction is allowed. Otherwise, the message will be rejected.
    * The public key only exists for looking up the associated private key on the server.
    * `hmac` in the Authorization Header is just a convenience since it's not part of the spec. If you really want to, you can substitute for whatever you want. I won't judge.

## Sample Server Code

```
const ApiKey = require('mongoose').model('User');
const passport = require('passport');
const HmacStrategy = require('passport-hmac-simple').Strategy;

passport.use(new HmacStrategy(
    function (publicKey, done) {
        User.findOne({publicKey}, function(err, user) {
            if (err) return done(err);
            if (!user) return done(null, false);
            done(null, user, user.privateKey);
        });
    }
));

// ... set up express/restify as usual ...

app.get('/sampleEndpoint',
    passport.authenticate('hmac', {session:false}),
    function (req, res) {
        // ... show your views here, etc. ...
    }
);
```

Note the example above does not save session info. You can turn on sessions via the normal Passport methods if you like, but I don't know the security risks involved. Caveat emptor.

## Sample Client Code

i.e. For jQuery:

```
$.post({
    url: '/sampleEndPoint',
    body: JSON.stringify({hello: 'world'}),
    contentType: 'application/json',
    headers: { Date: new Date().toUTCString() },
    success: function(responseData) {
        // ...so on and so forth.
    }
});
```

## To do?

I may or may not get around to these based on demand. List will be updated as I come across new items.

    * Customizable drift window
    * Custom InfoToSign schemes
    * HMAC-SHA256, etc. options