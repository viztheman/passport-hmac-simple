# passport-hmac-simple
Simple HMAC authentication for [Passport](https://passportjs.org) and [Node.js](https://nodejs.org).

Server side works like any other Passport strategy: Look up the private key (and optionally user model) associated with the public key, then pass them back as `done(null, user, privateKey)`.

## Algorithm

Signatures are generated according to the following pseudocode for GET/DELETE requests:

```
Full URL = Original URL + QueryString("timestamp", UNIX Timestamp)

InfoToSign = Method + "\n\n\n" +
    UTC Timestamp + "\n" +
    Full URL

HMAC = HMAC-SHA1(InfoToSign, PrivateKey, UTF-8) To Hex
base64HMAC = base64(HMAC)
Authorization Header = "hmac PublicKey:base64HMAC"
```

For POST/PUT/PATCH:

```
Full URL = Original URL + QueryString("timestamp", UNIX Timestamp)

InfoToSign = Method + "\n" +
    ContentType + "\n" +
    SHA1 Hash of Data + "\n" +
    UTC Timestamp + "\n" +
    Full URL

HMAC = HMAC-SHA1(InfoToSign, PrivateKey, UTF-8) To Hex
base64HMAC = base64(HMAC)
Authorization Header = "hmac PublicKey:base64HMAC"
```

`Full URL` includes query strings but _not_ schema, i.e. `/test?abc=1`. Unix timestamp is retrieved through `new Date().valueOf()`. UTC Timestamp can be retrieved through `new Date().toUTCString()`. Obviously, they should match.

Here's an example. Note how we've appended the appropriate timestamp.

```
InfoToSign = "GET\n\n\nTue, 30 Apr 2019 17:21:45 GMT\n/test?abc=1&timestamp=1556644905000"

HMAC = HMAC-SHA1(InfoToSign, "This is the private key", utf-8) To Hex
     = 0961ead1d940ffb6063037c1490b06620207f737

base64HMAC = 'MDk2MWVhZDFkOTQwZmZiNjA2MzAzN2MxNDkwYjA2NjIwMjA3ZjczNw==';
Authorization Header = "hmac MyPublicKey:MDk2MWVhZDFkOTQwZmZiNjA2MzAzN2MxNDkwYjA2NjIwMjA3ZjczNw==';
```

Some notes on the values being passed in:

* Private key should be sent to the user _once_ over a _secure_ channel such as email or HTTPS. It should _never_ be sent to the server after that.
* The public key only exists for looking up the associated private key on the server.
* Keys can be whatever you want, though random generation (i.e. GUIDs) is _strongly_ encouraged.
* Timestamp is checked server side to prevent replay attacks. There's a window of +/- 1 minute. UTC is internally used for javascript dates, so you shouldn't have to worry about time zones. Just `new Date().valueOf()` and pass it in!
* Right now, only JSON is supported as a content/body type. **You must use `JSON.stringify()`, or it will not work.**
* `hmac` in the Authorization Header is just a convenience since it's not part of the spec. If you really want to, you can substitute whatever you want. I won't judge.

## Sample Server Code

```
const User = require('mongoose').model('User');
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

// ... set up express/restify as usual ..
// You MUST include a bodyParser and queryParser, or this plugin won't work at all.
// ...

app.get('/sampleEndpoint',
    passport.authenticate('hmac', {session:false}),
    function (req, res) {
        // ... show your views here, etc. ...
    }
);
```

Note the example does not save session info. You can turn on sessions via the normal Passport methods if you like, but I don't know the security risks involved. Caveat emptor.

## Sample Client Code

Coming soon.
