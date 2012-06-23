/*jslint node: true */

// mostly inspired by werkzeug http://www.pocoo.org/projects/werkzeug/
// thanks for theire quality work.
var security = function () {
        "use strict";
        var charset, SEPARATOR, hashAlgotiyhmNames, hashAlgorithms, crypto = require('crypto');

        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        SEPARATOR = '$';
        hashAlgotiyhmNames = ['md4', 'md5', 'ripemd160', 'rmd160', 'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'whirlpool'];

        hashAlgorithms = function (name) {
            return crypto.createHash(name);

        };

        function safeStringComp(a, b) {
            // compare strings in a constant time (protection against time
            // based attack).
            // TODO : adding failure (bad typing and so) consitency
            var ret, i, x, y, rv = 0;

            if (a.length !== b.length) {
                ret = false;
            } else {
                for (i = 0; i < a.length; i += 1) {
                    x = a[i];
                    y = b[i];
                    rv += x.charCodeAt() - y.charCodeAt();
                }
                ret = rv === 0;
            }

            return ret;

        }

        function pickAChar() {
            return charset[Math.floor(Math.random() * charset.length)];
        }

        function genSalt(length) {
            var ret = '',
                i;
            length = length || 0;
            for (i = 0; i < length; i += 1) {
                ret += pickAChar();
            }
            return ret;
        }

        function hashInternal(method, salt, password) {
            var ret, h;
            if (method === 'plain') {
                ret = password;
            } else {
                // corrently not avaible, need to find out if
                // salted hash function can be initialisez right in 
                // 
                salt = salt || '';
                if (hashAlgotiyhmNames.indexOf(method) < 0) {
                    return undefined;
                }

                // TODO : developper have a poor comprehension of this part
                // of his own code, shame on him and be scared to
                // use it unit this part be reviewed.
                h = hashAlgorithms(method);
                h.update(salt + password + salt);
                ret = h.digest('hex');
            }

            return ret;
        }

        // BIGGER is better, does not hesitate to set an huge salt length value 
        // (actually default is 300).
        // md5 is pretty lame this times, please use at least sha1, but sha256 is 
        // useless anymore.
        // Return method$salt$hash
        function generatePasswordHash(password, method, saltLength) {
            var salt, hash;

            saltLength = saltLength || 300;
            if (method !== 'plain') {
                salt = genSalt(saltLength);
            } else {
                salt = '';
            }        

            hash = hashInternal(method, salt, password);
            return method + SEPARATOR + salt + SEPARATOR + hash;
        }

        function checkPasswordHash(pwHash, password) {
            var pwHashSplit, ret;

            pwHashSplit = pwHash.split(SEPARATOR);

            if (pwHashSplit.length !== 3) {
                ret = false;
            } else {
                ret = safeStringComp(hashInternal(pwHashSplit[0], pwHashSplit[1], password), pwHashSplit[2]);
            }

            return ret;
        }

        return {
            charset: charset,
            version: '0.0.0',
            generatePasswordHash: generatePasswordHash,
            checkPasswordHash: checkPasswordHash
        };
    };

module.exports = security();
