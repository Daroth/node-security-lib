var vows = require('vows'),
    assert = require('assert'),
    security = require('../');

function testHashMethod(method, testSuite) {
    testSuite[method] ={
        topic: function () {
            return security.generatePasswordHash('a', method);
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
testHashMethod('rmd160', testSuite);
testHashMethod('sha', testSuite);
testHashMethod('sha1', testSuite);
vows.describe('Security lib').addBatch(testSuite).exportTo(module);