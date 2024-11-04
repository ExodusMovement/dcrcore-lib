'use strict';
const { randomBytes } = require('@exodus/crypto/randomBytes')

function Random() {
}

/* secure random bytes that sometimes throws an error due to lack of entropy */
Random.getRandomBuffer = function(size) {
  return randomBytes(size)
};

/* insecure random bytes, but it never fails */
Random.getPseudoRandomBuffer = function(size) {
  // insecure random bytes removed, let's use secure variant everywhere or fail
  return Random.getRandomBuffer(size)
};

module.exports = Random;
