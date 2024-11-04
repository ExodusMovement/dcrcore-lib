'use strict';

const { hashSync } = require('@exodus/crypto/hash')
const { hmacSync } = require('@exodus/crypto/hmac')
var createHash = require('create-hash');
var createBlakeHash = require('blake-hash/js');
var BufferUtil = require('../util/buffer');
var $ = require('../util/preconditions');

var Hash = module.exports;

Hash.sha1 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return createHash('sha1').update(buf).digest();
};

Hash.sha1.blocksize = 512;

Hash.sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('sha256', buf);
};

Hash.sha256.blocksize = 512;

Hash.sha256sha256 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return Hash.sha256(Hash.sha256(buf));
};

Hash.ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('ripemd160', buf);
};

Hash.sha256ripemd160 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return hashSync('ripemd160', hashSync('sha256', buf));
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
  return createBlakeHash('blake256').update(buf).digest();
}

Hash.sha512 = function(buf) {
  $.checkArgument(BufferUtil.isBuffer(buf));
  return createHash('sha512').update(buf).digest();
};

Hash.sha512.blocksize = 1024;

Hash.sha256hmac = function(data, key) {
  $.checkArgument(BufferUtil.isBuffer(data));
  $.checkArgument(BufferUtil.isBuffer(key));
  return hmacSync('sha256', key, data)
};

Hash.sha512hmac = function(data, key) {
  $.checkArgument(BufferUtil.isBuffer(data));
  $.checkArgument(BufferUtil.isBuffer(key));
  return hmacSync('sha512', key, data)
};
