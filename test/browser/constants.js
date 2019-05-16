var PUBLIC_KEY = '721cfc32-7f37-43f8-aeb5-13c240d36d00';
var PRIVATE_KEY = '71d366bc-8489-450a-974a-61ff798f2404';
var BAD_PRIVATE_KEY = 'ca7c9ef9-39bb-4cc8-bb2d-0ea421b05dd8';

var TEST_URL = '/test/url';
var DATA = {a: 1, b: 2};

var RGX_VALID_HASH = /^[0-9a-fA-F]+$/;

// Format: hmac <PUBLICKEY>:<BASE64>
var RGX_VALID_AUTH_HEADER = new RegExp('^hmac ' + PUBLIC_KEY + ':([A-Za-z0-9+/=]+)$');

function stampUrl(url, timestamp) {
    return url
        + (url.indexOf('?') < 0 ? '?' : '&')
        + 'timestamp=' + timestamp.valueOf().toString();
}

function createGetSig(url, timestamp) {
    return [
        'GET',
        '',
        '',
        timestamp.toUTCString(),
        stampUrl(url, timestamp)
    ].join('\n');
}

function createPostSig(url, timestamp, data) {
    var body = JSON.stringify(data);
    var contentMd5 = CryptoJS.MD5(body).toString();

    return [
        'POST',
        'application/json',
        contentMd5,
        timestamp.toUTCString(),
        stampUrl(url, timestamp)
    ].join('\n');
}
