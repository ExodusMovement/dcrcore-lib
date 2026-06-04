'use strict';

require('chai').should();

var bitcore = require('../../index-test');
var Transaction = bitcore.Transaction;

describe('Transaction', function() {

  describe('#fromObject', function() {

    it('builds from a Transaction instance and preserves its data', function() {
      var source = new Transaction().lockUntilBlockHeight(123);

      var target = new Transaction().fromObject(source);

      target.nLockTime.should.equal(123);
      target.toObject().should.deep.equal(source.toObject());
    });

  });

});
