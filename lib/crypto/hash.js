'use strict';

const { hashSync } = require('@exodus/crypto/hash')
const { sha1 } = require('@noble/hashes/sha1')
var BufferUtil = require('../util/buffer');
var $ = require('../util/preconditions');

var Hash = module.exports;

Hash.sha1 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Buffer.from(sha1(buf));
};

Hash.sha1.blocksize = 512;

Hash.sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('sha256', buf, 'buffer');
};

Hash.sha256.blocksize = 512;

Hash.sha256sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.sha256(Hash.sha256(buf));
};

Hash.ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('ripemd160', buf, 'buffer');
};

Hash.sha256ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('ripemd160', hashSync('sha256', buf), 'buffer');
};

Hash.blake256ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.ripemd160(Hash.blake256(buf));
}

Hash.doubleblake256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.blake256(Hash.blake256(buf));
}

Hash.blake256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('blake256', buf, 'buffer');
}

Hash.sha512 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('sha512', buf, 'buffer');
};

Hash.sha512.blocksize = 1024;
