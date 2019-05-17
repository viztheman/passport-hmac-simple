# passport-hmac-simple
Simple HMAC authentication for [Passport](https://passportjs.org) and [Node.js](https://nodejs.org).

Besides doing the proper hashing, it also uses timestamps to prevent replay attacks. `passReqToCallback` is also supported if you're into that sort of thing. I don't judge.


## Sample Code

### Server

    const User = require('mongoose').model('User');
    const passport = require('passport');
    const HmacStrategy = require('passport-hmac-simple').Strategy;

    // Do the regular passport setup, then call...

    passport.use(new HmacStrategy(async function(publicKey, done) {
        try {
            let user = await User.find({publicKey});

            if (!user || !user.privateKey)
                return done(null, false);

            done(null, user, user.privateKey);
        }
        catch (e) {
            done(e);
        }
    }));

    // ...then set up and use passport as normal.

### Client
Include [jQuery](https://jquery.com/), [CryptoJS](https://code.google.com/archive/p/crypto-js/), and `dist/passport-hmac-simple.js` on the page however you like.

Note that `success` and `error` callbacks are passed straight into `$.ajax`, so you shouldn't have to do anything different than normal jQuery AJAX.

##### GET, DELETE

    var PUBLIC_KEY = 'xyz123';
    var PRIVATE_KEY = 'Thisisasecret';

    var hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);

    // or: hmac.delete
    hmac.get(
        '/api/endpointUrl?id=123',
        function success(data) { ... },
        function error() { ... }
    );

##### POST, PUT, PATCH
`application/json` is used by default and is (currently?) the only method of postback supported.

    var PUBLIC_KEY = 'xyz123';
    var PRIVATE_KEY = 'Thisisasecret';
    var hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);

    // or: hmac.put, etc.
    hmac.post(
        '/api/endpointUrl',
        {a: 1, b: 2},   // Pass the regular object, not the JSON string
        function success(data) { ... },
        function error() { ... }
    );
    
## Algorithm Pseudocode

##### GET, DELETE

    Full URL = Original URL + AddQueryString("timestamp", now.valueOf().toString())

    InfoToSign = Method + "\n" +
        "\n" +
        "\n" +
        now.toUTCString() + "\n" +
        Full URL

    HMAC = HMAC-SHA1(InfoToSign as UTF-8, PrivateKey) To Hex
    base64HMAC = base64(HMAC)
    Authorization Header = "hmac PublicKey:base64HMAC"

##### POST, PUT, PATCH

Only `application/json` is currently accepted as a content type.

`Content-MD5` is set solely through the HTTP header. It doesn't matter much if it's not right since the hash check will still fail.
    
    Full URL = Original URL + QueryString("timestamp", now.valueOf().toString())

    InfoToSign = Method + "\n" +
        ContentType + "\n" +
        Content-MD5 + "\n" +
        now.toUTCString() +
        Full URL

    HMAC = HMAC-SHA1(InfoToSign, PrivateKey, UTF-8) To Hex
    base64HMAC = base64(HMAC)
    Authorization Header = "hmac PublicKey:base64HMAC"


