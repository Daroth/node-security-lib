var vows = require('vows'),
    assert = require('assert'),
    security = require('../');

function testHashMethod(method, testSuite) {
    testSuite[method] ={
        topic: function () {
            var hash = security.generatePasswordHash('a', method);
            console.log('method : ' + method + ' hash : ' + hash);
            return hash;
        },
        'Should be equals': function (topic) {
            assert.isTrue(security.checkPasswordHash(topic, 'a'));
        },
        'Should be differents': function (topic) {
            assert.isFalse(security.checkPasswordHash(topic, 'b'));
        }
    };
}

var testSuite = {};
testHashMethod('md4', testSuite);
testHashMethod('md5', testSuite);
testHashMethod('ripemd160', testSuite);
testHashMethod('rmd160', testSuite);
testHashMethod('sha', testSuite);
testHashMethod('sha1', testSuite);
testHashMethod('sha224', testSuite);
testHashMethod('sha256', testSuite);
testHashMethod('sha384', testSuite);
testHashMethod('sha512', testSuite);
testHashMethod('whirlpool', testSuite);
vows.describe('Security lib').addBatch(testSuite).exportTo(module);
