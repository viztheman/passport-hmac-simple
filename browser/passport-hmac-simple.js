/*
 * Requirements: Crypto.js, jQuery
 */

var Hmac;

(function($, CryptoJS) {
    'use strict';

    Hmac = function(publicKey, privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    };

    Hmac.prototype.createSig = function(info) {
        var url = info.url +
            (info.url.indexOf('?') >= 0 ? '&' : '?') +
            'timestamp=' + info.timestamp.valueOf().toString();

        return [
            info.method,
            info.contentType || '',
            info.data || '',
            info.timestamp.toUTCString(),
            url
        ].join('\n');
    };

    Hmac.prototype.createHash = function(info) {
        var sig = this.createSig(info);
        var hash = CryptoJS.HmacSHA1(sig, this.privateKey);
        return btoa(hash);
    };

    Hmac.prototype.createAuthHeader = function(info) {
        return 'hmac ' + this.publicKey + ':' + this.createHash(info);
    };

    Hmac.prototype.sendQuery = function(method, url, success, error) {
        var info = {
            method: method,
            timestamp: new Date(),
            url: url
        };

        $.ajax({
            type: method,
            url: url,
            headers: {'Authorization': this.createAuthHeader(info)},
            success: success,
            error: error
        });
    };

    // Only JSON support (for now).
    Hmac.prototype.sendBody = function(method, url, data, success, error) {
        var info = {
            method: method,
            timestamp: new Date(),
            contentType: 'application/json',
            body: JSON.stringify(body),
            url: url
        };

        $.ajax({
            type: method,
            url: url,
            dataType: 'json',
            data: info.body,
            headers: {'Authorization': this.createAuthHeader(info)}
        });
    };

    Hmac.prototype.get = function(url, success, error) {
        return this.sendQuery('GET', url, success, error);
    };

    Hmac.prototype.post = function(url, data, success, error) {
        return this.sendBody('POST', url, data, success, error);
    };

    Hmac.prototype.put = function(url, data, success, error) {
        return this.sendBody('PUT', url, data, success, error);
    };

    Hmac.prototype.patch = function(url, data, success, error) {
        return this.sendBody('PATCH', url, data, success, error);
    };

    Hmac.prototype.delete = function(url, data, success, error) {
        return this.sendQuery('DELETE', url, data, success, error);
    };

})(jQuery, CryptoJS);
