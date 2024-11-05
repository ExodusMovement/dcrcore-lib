'use strict';

var BN = require('bn.js');
var $ = require('../util/preconditions');
var _ = require('lodash');

var reversebuf = function(buf) {
  return Buffer.from(buf).reverse()
};

exports.Zero = new BN(0);
exports.One = new BN(1);

exports.fromNumber = function(n) {
  $.checkArgument(_.isNumber(n));
  return new BN(n);
};

exports.fromString = function(str, base) {
  $.checkArgument(_.isString(str));
  return new BN(str, base);
};

function fromBuffer(buf, opts) {
  if (typeof opts !== 'undefined' && opts.endian === 'little') {
    buf = reversebuf(buf);
  }
  var hex = buf.toString('hex');
  var bn = new BN(hex, 16);
  return bn;
};

exports.fromBuffer = fromBuffer

/**
 * Instantiate a BigNumber from a "signed magnitude buffer"
 * (a buffer where the most significant bit represents the sign (0 = positive, -1 = negative))
 */
function fromSM(buf, opts) {
  var ret;
  if (buf.length === 0) {
    return fromBuffer(Buffer.from([0]));
  }

  var endian = 'big';
  if (opts) {
    endian = opts.endian;
  }
  if (endian === 'little') {
    buf = reversebuf(buf);
  }

  if (buf[0] & 0x80) {
    buf[0] = buf[0] & 0x7f;
    ret = fromBuffer(buf);
    ret.neg().copy(ret);
  } else {
    ret = fromBuffer(buf);
  }
  return ret;
};

exports.toNumber = function(bn) {
  return parseInt(bn.toString(10), 10);
};

exports.toBuffer = function(bn, opts) {
  var buf, hex;
  if (opts && opts.size) {
    hex = bn.toString(16, 2);
    var natlen = hex.length / 2;
    buf = Buffer.from(hex, 'hex');

    if (natlen === opts.size) {
      buf = buf;
    } else if (natlen > opts.size) {
      buf = trim(buf, natlen);
    } else if (natlen < opts.size) {
      buf = pad(buf, natlen, opts.size);
    }
  } else {
    hex = bn.toString(16, 2);
    buf = Buffer.from(hex, 'hex');
  }

  if (typeof opts !== 'undefined' && opts.endian === 'little') {
    buf = reversebuf(buf);
  }

  return buf;
};

function toSMBigEndian(bn) {
  var buf;
  if (bn.cmp(exports.Zero) === -1) {
    buf = exports.toBuffer(bn.neg());
    if (buf[0] & 0x80) {
      buf = Buffer.concat([Buffer.from([0x80]), buf]);
    } else {
      buf[0] = buf[0] | 0x80;
    }
  } else {
    buf = exports.toBuffer(bn);
    if (buf[0] & 0x80) {
      buf = Buffer.concat([Buffer.from([0x00]), buf]);
    }
  }

  if (buf.length === 1 & buf[0] === 0) {
    buf = Buffer.alloc(0);
  }
  return buf;
};

function toSM(bn, opts) {
  var endian = opts ? opts.endian : 'big';
  var buf = toSMBigEndian(bn);

  if (endian === 'little') {
    buf = reversebuf(buf);
  }
  return buf;
};

/**
 * Create a BN from a "ScriptNum":
 * This is analogous to the constructor for CScriptNum in bitcoind. Many ops in
 * bitcoind's script interpreter use CScriptNum, which is not really a proper
 * bignum. Instead, an error is thrown if trying to input a number bigger than
 * 4 bytes. We copy that behavior here. A third argument, `size`, is provided to
 * extend the hard limit of 4 bytes, as some usages require more than 4 bytes.
 */
exports.fromScriptNumBuffer = function(buf, fRequireMinimal, size) {
  var nMaxNumSize = size || 4;
  $.checkArgument(buf.length <= nMaxNumSize, new Error('script number overflow'));
  if (fRequireMinimal && buf.length > 0) {
    // Check that the number is encoded with the minimum possible
    // number of bytes.
    //
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if ((buf[buf.length - 1] & 0x7f) === 0) {
      // One exception: if there's more than one byte and the most
      // significant bit of the second-most-significant-byte is set
      // it would conflict with the sign bit. An example of this case
      // is +-255, which encode to 0xff00 and 0xff80 respectively.
      // (big-endian).
      if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) === 0) {
        throw new Error('non-minimally encoded script number');
      }
    }
  }
  return fromSM(buf, { endian: 'little' });
};

/**
 * The corollary to the above, with the notable exception that we do not throw
 * an error if the output is larger than four bytes. (Which can happen if
 * performing a numerical operation that results in an overflow to more than 4
 * bytes).
 */
exports.toScriptNumBuffer = function(bn) {
  return toSM(bn, { endian: 'little' });
};

exports.gt = function(a, b) {
  return a.cmp(b) > 0;
};

exports.gte = function(a, b) {
  return a.cmp(b) >= 0;
};

exports.lt = function(a, b) {
  return a.cmp(b) < 0;
};

function trim(buf, natlen) {
  return buf.slice(natlen - buf.length, buf.length);
};

function pad(buf, natlen, size) {
  var rbuf = Buffer.alloc(size);
  for (var i = 0; i < buf.length; i++) {
    rbuf[rbuf.length - 1 - i] = buf[buf.length - 1 - i];
  }
  for (i = 0; i < size - natlen; i++) {
    rbuf[i] = 0;
  }
  return rbuf;
};

exports.BN = BN;
