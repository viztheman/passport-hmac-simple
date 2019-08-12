if (typeof global !== 'undefined')
    global.fetch = require('node-fetch');

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
		var contentMd5 = '';

		if (info.data) {
			var body = JSON.stringify(info.data);

			if (!CryptoJS)
				contentMd5 = require('crypto')
					.createHash('md5')
					.update(Buffer.from(body, 'utf-8'))
					.digest('hex');
			else
				contentMd5 = CryptoJS.MD5(body);
		}

		return [
			info.method,
			info.contentType || '',
			contentMd5,
			info.timestamp.toUTCString(),
			this.createTimestampUrl(info.url, info.timestamp)
		].join('\n');
};

Hmac.prototype.createHash = function(info) {
		var sig = this.createSig(info);

		if (!CryptoJS)
			return require('crypto')
				.createHmac('sha1', this.privateKey)
				.update(Buffer.from(sig, 'utf-8'))
				.digest('hex');

		return CryptoJS.HmacSHA1(sig, this.privateKey);
};

Hmac.prototype.createAuthHeader = function(info) {
        let hash = this.createHash(info);

        let b64 = typeof btoa !== 'undefined'
            ? btoa(hash)
            : Buffer.from(hash).toString('base64');

		return 'hmac ' + this.publicKey + ':' + b64;
};

Hmac.prototype.sendQueryReturnTimestamp = function(method, url, success, error) {
		var info = {
			method: method,
			timestamp: new Date(),
			url: url.replace(/^https?:\/\/[^\/]+/, '')
		};

		fetch(
			this.createTimestampUrl(url, info.timestamp),
			{
				method: info.method,
				headers: {
					'Authorization': this.createAuthHeader(info)
				}
			}
		)
		.then(res => res.json())
        .then(success)
		.catch(error);

		return info.timestamp;
};

// Only JSON support (for now).
Hmac.prototype.sendBodyReturnTimestamp = function(method, url, data, success, error) {
		var info = {
			method: method,
			contentType: 'application/json',
			body: JSON.stringify(data),
			timestamp: new Date(),
			url: url.replace(/^https?:\/\/[^\/]+/, '')
		};

		fetch(
			this.createTimestampUrl(url, info.timestamp),
			{
				method,
				body: info.body,
				headers: {
					'Authorization': this.createAuthHeader(info),
					'Content-Type': 'application/json'
				}
			}
		)
		.then(res => res.json())
        .then(success)
		.catch(error);

		return info.timestamp;
};

Hmac.prototype.get = function(url, success, error) {
		return this.sendQueryReturnTimestamp('GET', url, success, error);
};

Hmac.prototype.post = function(url, data, success, error) {
		return this.sendBodyReturnTimestamp('POST', url, data, success, error);
};

Hmac.prototype.put = function(url, data, success, error) {
		return this.sendBodyReturnTimestamp('PUT', url, data, success, error);
};

Hmac.prototype.patch = function(url, data, success, error) {
		return this.sendBodyReturnTimestamp('PATCH', url, data, success, error);
};

Hmac.prototype.delete = function(url, success, error) {
		return this.sendQueryReturnTimestamp('DELETE', url, success, error);
};

if (typeof module !== 'undefined')
		module.exports = Hmac;
