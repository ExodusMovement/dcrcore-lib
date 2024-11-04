'use strict';

const { sign, verify } = require('./ecdsa')
const { randomBytes } = require('@exodus/crypto/randomBytes')

var ECDSA = function ECDSA(obj) {
  if (!(this instanceof ECDSA)) {
    return new ECDSA(obj);
  }
  if (obj) {
    this.set(obj);
  }
};

/* jshint maxcomplexity: 9 */
ECDSA.prototype.set = function(obj) {
  this.hashbuf = obj.hashbuf || this.hashbuf;
  this.endian = obj.endian || this.endian; //the endianness of hashbuf
  this.privkey = obj.privkey || this.privkey;
  this.pubkey = obj.pubkey || (this.privkey ? this.privkey.publicKey : this.pubkey);
  this.sig = obj.sig || this.sig;
  this.verified = obj.verified || this.verified;
  return this;
};

ECDSA.prototype.privkey2pubkey = function() {
  this.pubkey = this.privkey.toPublicKey();
};

ECDSA.fromString = function(str) {
  var obj = JSON.parse(str);
  return new ECDSA(obj);
};

ECDSA.prototype.sign = function() {
  this.sig = ECDSA.sign(this.hashbuf, this.privkey, this.endian)
  return this
};

ECDSA.prototype.signRandomK = function() {
  this.sig = ECDSA.sign(this.hashbuf, this.privkey, this.endian, randomBytes(32))
  return this
};

ECDSA.prototype.verify = function() {
  this.verified = ECDSA.verify(this.hashbuf, this.sig, this.pubkey, this.endian)
  return this
};

ECDSA.sign = sign
ECDSA.verify = verify

module.exports = ECDSA;
