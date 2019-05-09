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

    Hmac.prototype.createTimestampUrl = function(url, timestamp) {
        return url +
            (url.indexOf('?') >= 0 ? '&' : '?') +
            'timestamp=' + timestamp.valueOf().toString();
    };

    Hmac.prototype.createSig = function(info) {
        return [
            info.method,
            info.contentType || '',
            info.data || '',
            info.timestamp.toUTCString(),
            this.createTimestampUrl(info.url, info.timestamp)
        ].join('\n');
    };

    Hmac.prototype.createHash = function(info) {
        var sig = this.createSig(info);
        return CryptoJS.HmacSHA1(sig, this.privateKey);
    };

    Hmac.prototype.createAuthHeader = function(info) {
        return 'hmac ' + this.publicKey + ':' + btoa(this.createHash(info));
    };

    Hmac.prototype.sendQuery = function(method, url, success, error) {
        var info = {
            method: method,
            timestamp: new Date(),
            url: url
        };

        $.ajax({
            type: method,
            url: this.createTimestampUrl(info.url, info.timestamp),
            headers: {'Authorization': this.createAuthHeader(info)},
            success: success,
            error: error
        });
        
        return info.timestamp;
    };

    // Only JSON support (for now).
    Hmac.prototype.sendBody = function(method, url, data, success, error) {
        var info = {
            method: method,
            timestamp: new Date(),
            contentType: 'application/json',
            body: JSON.stringify(data),
            url: url
        };

        $.ajax({
            type: method,
            url: this.createTimestampUrl(info.url, info.timestamp),
            dataType: 'json',
            data: info.body,
            headers: {'Authorization': this.createAuthHeader(info)},
            success: success,
            error: error
        });
        
        return info.timestamp;
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

    Hmac.prototype.delete = function(url, success, error) {
        return this.sendQuery('DELETE', url, success, error);
    };

})(jQuery, CryptoJS);
