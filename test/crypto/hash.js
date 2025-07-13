'use strict';

require('chai').should();
var bitcore = require('../../index-test');
var Hash = bitcore.crypto.Hash;

describe('Hash', function() {
  var buf = new Buffer([0, 1, 2, 3, 253, 254, 255]);
  var str = 'test string';

  describe('@sha1', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.sha1(buf);
      hash.toString('hex').should.equal('de69b8a4a5604d0486e6420db81e39eb464a17b2');
      hash = Hash.sha1(new Buffer(0));
      hash.toString('hex').should.equal('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    });

    it('throws an error when the input is not a buffer', function() {
      Hash.sha1.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#sha256', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.sha256(buf);
      hash.toString('hex').should.equal('6f2c7b22fd1626998287b3636089087961091de80311b9279c4033ec678a83e8');
    });

    it('fails when the input is not a buffer', function() {
      Hash.sha256.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#sha256sha256', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.sha256sha256(buf);
      hash.toString('hex').should.equal('be586c8b20dee549bdd66018c7a79e2b67bb88b7c7d428fa4c970976d2bec5ba');
    });

    it('fails when the input is not a buffer', function() {
      Hash.sha256sha256.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#sha256ripemd160', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.sha256ripemd160(buf);
      hash.toString('hex').should.equal('7322e2bd8535e476c092934e16a6169ca9b707ec');
    });

    it('fails when the input is not a buffer', function() {
      Hash.sha256ripemd160.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#blake256ripemd160', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.blake256ripemd160(buf);
      hash.toString('hex').should.equal('468394f9ea4c98edbe393e8fdf35f8340cf19f58');
    });

    it('fails when the input is not a buffer', function() {
      Hash.blake256ripemd160.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#ripemd160', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.ripemd160(buf);
      hash.toString('hex').should.equal('fa0f4565ff776fee0034c713cbf48b5ec06b7f5c');
    });

    it('fails when the input is not a buffer', function() {
      Hash.ripemd160.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

  describe('#sha512', function() {

    it('calculates the hash of this buffer correctly', function() {
      var hash = Hash.sha512(buf);
      hash.toString('hex')
        .should.equal('c0530aa32048f4904ae162bc14b9eb535eab6c465e960130005fedd' +
          'b71613e7d62aea75f7d3333ba06e805fc8e45681454524e3f8050969fe5a5f7f2392e31d0');
    });

    it('fails when the input is not a buffer', function() {
      Hash.sha512.bind(Hash, str).should.throw('Invalid Argument');
    });

  });

});
