'use strict';

const { hmacSync } = require('@exodus/crypto/hmac')
const secp256k1 = require('@noble/secp256k1')
const BNUtil = require('./bn')
var Signature = require('./signature');
var BufferUtil = require('../util/buffer');
var _ = require('lodash');
var $ = require('../util/preconditions');

if (!secp256k1.utils.hmacSha256Sync) {
  secp256k1.utils.hmacSha256Sync = (key, ...msgs) => hmacSync('sha256', key, msgs, 'uint8')
}

exports.sign = function(hashbuf, privkey, endian, extraEntropy) {
  if (extraEntropy !== undefined) {
    if (!(extraEntropy instanceof Uint8Array)) throw new Error('Expected extraEntropy Uint8Array')
    if (extraEntropy.length !== 32) throw new Error('Expected extraEntropy to be of length 32')
  }
  if (!(hashbuf instanceof Uint8Array)) throw new Error('Expected Uint8Array')
  $.checkState(hashbuf && privkey && privkey.bn, new Error('invalid parameters'));
  $.checkState(BufferUtil.isBuffer(hashbuf) && hashbuf.length === 32, new Error('hashbuf must be a 32 byte buffer'));
  if (endian === 'little') hashbuf = (Buffer.from(hashbuf)).reverse()
  const privbuf = BNUtil.toBuffer(privkey.bn, { size: 32 })
  const der = secp256k1.signSync(hashbuf, privbuf)
  const sig = Signature.fromDER(Buffer.from(der))
  sig.compressed = privkey.publicKey.compressed
  return sig
};

exports.verify = function(hashbuf, sig, pubkey, endian) {
  if (!(hashbuf instanceof Uint8Array)) throw new Error('Expected Uint8Array')
  if (endian === 'little') hashbuf = (Buffer.from(hashbuf)).reverse()
  const pubbuf = pubkey.toDER()
  const der = sig.toDER()
  return secp256k1.verify(der, hashbuf, pubbuf, { strict: false }) // allows highS per specific test
};
