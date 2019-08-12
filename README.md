# passport-hmac-simple
HMAC authentication for [Passport](https://www.passportjs.org) and [Node.js](https://nodejs.org), complete with client.

Besides doing the proper hashing, it also uses timestamps to prevent replay attacks.

## Server

    // We use mongoose as an example, but feel free to store the user
    // however you like.
    //
    // Example Schema: {publicKey: 'XXX', privateKey: 'YYY'}
    //
    const User = require('mongoose').model('User');

    const passport = require('passport');
    const HmacStrategy = require('passport-hmac-simple').Strategy;

    // Do the regular passport initialization, then call...

    passport.use(new HmacStrategy(async function(publicKey, done) {
        try {
            let user = await User.findOne({publicKey});

            if (!user || !user.privateKey)
                return done(null, false);

            done(null, user, user.privateKey);
        }
        catch (e) {
            done(e);
        }
    }));

    // ...now, set up and use passport as normal.

## Client
The same client code should work for both Node.js require() and simple javascript tags.

### Node.js

    const Hmac = require('passport-hmac-simple').Hmac;

### Javascript

**You'll need Fetch API and [CryptoJS](https://code.google.com/archive/p/crypto-js/) in order to use the client browser side.** If your browser doesn't support Fetch API (cough cough IE), you'll need a (polyfill)[https://github.com/github/fetch].

    <!-- Make this file to your page however you like. -->
    <script src="passport-hmac-simple/lib/Hmac.js"></script>

### GET, DELETE

    var PUBLIC_KEY = 'xyz123';
    var PRIVATE_KEY = 'Thisisasecret';

    var hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);

    hmac.get(   // or: hmac.delete
        '/api/endpointUrl?id=123',
        function success(json) { ... },
        function error(err) { ... }
    );

### POST, PUT, PATCH

    var PUBLIC_KEY = 'xyz123';
    var PRIVATE_KEY = 'Thisisasecret';
    var hmac = new Hmac(PUBLIC_KEY, PRIVATE_KEY);

    
    hmac.post(      // or: hmac.put, etc.
        '/api/endpointUrl',
        {a: 1, b: 2},   // Pass the object, not the JSON string
        function success(json) { ... },
        function error(err) { ... }
    );
    
## Algorithm Pseudocode

You shouldn't need any of this to use the module, but it's here if you want it.

### GET, DELETE

    Full URL = URL + AddQueryString("timestamp", now.valueOf().toString())

    InfoToSign = Method + "\n" +
        "\n" +
        "\n" +
        now.toUTCString() + "\n" +
        Path

    HMAC = HMAC-SHA1(InfoToSign as UTF-8, PrivateKey) To Hex
    base64HMAC = base64(HMAC)
    Authorization Header = "hmac PublicKey:base64HMAC"

### POST, PUT, PATCH

Only `application/json` is currently accepted as a content type.

`Content-MD5` is set solely through the (similarly named) HTTP header. If it's wrong or missing, authentication will fail.
    
    Full URL = URL + QueryString("timestamp", now.valueOf().toString())

    InfoToSign = Method + "\n" +
        ContentType + "\n" +
        Content-MD5 + "\n" +
        now.toUTCString() +
        Path

    HMAC = HMAC-SHA1(InfoToSign, PrivateKey, UTF-8) To Hex
    base64HMAC = base64(HMAC)
    Authorization Header = "hmac PublicKey:base64HMAC"
