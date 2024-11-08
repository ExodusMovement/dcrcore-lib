'use strict';

const secp256k1 = require('@noble/secp256k1')
const BNUtil = require('./crypto/bn');
const { BN } = BNUtil;
var Hash = require('./crypto/hash');
var JSUtil = require('./util/js');
var Network = require('./networks');
var _ = require('lodash');
var $ = require('./util/preconditions');

const fromExtra = Object.create(null) // private object for === check

/**
 * Instantiate a PublicKey from a {@link PrivateKey}, {@link Point}, `string`, or `Buffer`.
 *
 * There are two internal properties, `network` and `compressed`, that deal with importing
 * a PublicKey from a PrivateKey in WIF format. More details described on {@link PrivateKey}
 *
 * @example
 * ```javascript
 * // instantiate from a private key
 * var key = PublicKey(privateKey, true);
 *
 * // export to as a DER hex encoded string
 * var exported = key.toString();
 *
 * // import the public key
 * var imported = PublicKey.fromString(exported);
 * ```
 *
 * @param {string} data - The encoded data in various formats
 * @param {Object} extra - additional options
 * @param {Network=} extra.network - Which network should the address for this public key be for
 * @param {String=} extra.compressed - If the public key is compressed
 * @returns {PublicKey} A new valid instance of an PublicKey
 * @constructor
 */
function PublicKey(data, extra) {

  if (!(this instanceof PublicKey)) {
    return new PublicKey(data, extra);
  }

  $.checkArgument(data, 'First argument is required, please include public key data.');

  if (data instanceof PublicKey) {
    // Return copy, but as it's an immutable object, return same argument
    return data;
  }
  extra = extra || {};

  let info = Object.create(null);

  // detect type of data
  if (data === fromExtra && extra.buf) {
    // Wrapped buf in extra
    info.buf = extra.buf
    info.compressed = (extra.compressed === undefined) || extra.compressed
  } else if (data.x && data.y) {
    const x = new BN(data.x, 'hex');
    const y = new BN(data.y, 'hex');
    info.buf = Buffer.from('04' + x.toString(16, 64) + y.toString(16, 64), 'hex')
    info.compressed = (data.compressed === undefined) || data.compressed
  } else if (typeof(data) === 'string') {
    info = PublicKey._transformDER(Buffer.from(data, 'hex'));
  } else if (PublicKey._isBuffer(data)) {
    info = PublicKey._transformDER(data);
  } else if (PublicKey._isPrivateKey(data)) {
    info = PublicKey._transformPrivateKey(data);
  } else {
    throw new TypeError('First argument is an unrecognized data format.');
  }
  if (!info.network) {
    info.network = _.isUndefined(extra.network) ? undefined : Network.get(extra.network);
  }

  // validation
  if (!secp256k1.Point.fromHex(info.buf)) throw new Error('Invalid point')

  JSUtil.defineImmutable(this, {
    buf: info.buf,
    compressed: info.compressed,
    network: info.network || Network.defaultNetwork
  });

  return this;
};

/**
 * Internal function to detect if an object is a {@link PrivateKey}
 *
 * @param {*} param - object to test
 * @returns {boolean}
 * @private
 */
PublicKey._isPrivateKey = function(param) {
  var PrivateKey = require('./privatekey');
  return param instanceof PrivateKey;
};

/**
 * Internal function to detect if an object is a Buffer
 *
 * @param {*} param - object to test
 * @returns {boolean}
 * @private
 */
PublicKey._isBuffer = function(param) {
  return (param instanceof Buffer) || (param instanceof Uint8Array);
};

/**
 * Internal function to transform a private key into a public key point
 *
 * @param {PrivateKey} privkey - An instance of PrivateKey
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformPrivateKey = function(privkey) {
  $.checkArgument(PublicKey._isPrivateKey(privkey), 'Must be an instance of PrivateKey');
  const privbuf = BNUtil.toBuffer(privkey.bn, { size: 32 })
  var info = Object.create(null);
  info.buf = Buffer.from(secp256k1.getPublicKey(privbuf, false))
  info.compressed = privkey.compressed;
  info.network = privkey.network;
  return info;
};

/**
 * Internal function to transform DER into a public key point
 *
 * @param {Buffer} buf - An hex encoded buffer
 * @param {bool=} strict - if set to false, will loosen some conditions
 * @returns {Object} An object with keys: point and compressed
 * @private
 */
PublicKey._transformDER = function(buf, strict) {
  /* jshint maxstatements: 30 */
  /* jshint maxcomplexity: 12 */
  $.checkArgument(PublicKey._isBuffer(buf), 'Must be a hex buffer of DER encoded public key');
  var info = Object.create(null);

  strict = _.isUndefined(strict) ? true : strict;

  if (buf[0] === 0x04 || (!strict && (buf[0] === 0x06 || buf[0] === 0x07))) {
    if (buf.length !== 65) {
      throw new TypeError('Length of x and y must be 32 bytes');
    }
    info.buf = Buffer.from(buf)
    info.compressed = false;
  } else if (buf[0] === 0x03 || buf[0] === 0x02) {
    info.buf = Buffer.from(secp256k1.Point.fromHex(buf).toRawBytes(false))
    info.compressed = true;
  } else {
    throw new TypeError('Invalid DER format public key');
  }
  return info;
};

/**
 * Instantiate a PublicKey from a PrivateKey
 *
 * @param {PrivateKey} privkey - An instance of PrivateKey
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromPrivateKey = function(privkey) {
  $.checkArgument(PublicKey._isPrivateKey(privkey), 'Must be an instance of PrivateKey');
  var info = PublicKey._transformPrivateKey(privkey);
  return new PublicKey(fromExtra, info);
};

/**
 * Instantiate a PublicKey from a Buffer
 * @param {Buffer} buf - A DER hex buffer
 * @param {bool=} strict - if set to false, will loosen some conditions
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromDER = PublicKey.fromBuffer = function(buf, strict) {
  $.checkArgument(PublicKey._isBuffer(buf), 'Must be a hex buffer of DER encoded public key');
  var info = PublicKey._transformDER(buf, strict);
  return new PublicKey(fromExtra, info);
};

/**
 * Instantiate a PublicKey from a DER hex encoded string
 *
 * @param {string} str - A DER hex string
 * @param {String=} encoding - The type of string encoding
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromString = function(str, encoding) {
  return new PublicKey(Buffer.from(str, encoding || 'hex'));
};

/**
 * Instantiate a PublicKey from an X Point
 *
 * @param {Boolean} odd - If the point is above or below the x axis
 * @param {Point} x - The x point
 * @returns {PublicKey} A new valid instance of PublicKey
 */
PublicKey.fromX = function(odd, x) {
  $.checkArgument(typeof odd === 'boolean', 'Must specify whether y is odd or not (true or false)');
  const pub = Buffer.from((odd ? '03' : '02') + (new BN(x, 'hex')).toString(16, 64), 'hex')
  return new PublicKey(pub);
};

/**
 * Check if there would be any errors when initializing a PublicKey
 *
 * @param {string} data - The encoded data in various formats
 * @returns {null|Error} An error if exists
 */
PublicKey.getValidationError = function(data) {
  var error;
  try {
    /* jshint nonew: false */
    new PublicKey(data);
  } catch (e) {
    error = e;
  }
  return error;
};

/**
 * Check if the parameters are valid
 *
 * @param {string} data - The encoded data in various formats
 * @returns {Boolean} If the public key would be valid
 */
PublicKey.isValid = function(data) {
  return !PublicKey.getValidationError(data);
};

/**
 * @returns {Object} A plain object of the PublicKey
 */
PublicKey.prototype.toObject = PublicKey.prototype.toJSON = function toObject() {
  return {
    x: this.buf.subarray(1, 33).toString('hex'),
    y: this.buf.subarray(33, 65).toString('hex'),
    compressed: this.compressed
  };
};

/**
 * Will output the PublicKey to a DER Buffer
 *
 * @returns {Buffer} A DER hex encoded buffer
 */
PublicKey.prototype.toBuffer = PublicKey.prototype.toDER = function() {
  if (!this.compressed) return Buffer.from(this.buf)
  return Buffer.from(secp256k1.Point.fromHex(this.buf).toRawBytes(this.compressed))
};

/**
 * Will return a blake256 + ripemd160 hash of the serialized public key
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/pubkey.h#L141
 * @returns {Buffer}
 */
PublicKey.prototype._getID = function _getID() {
  return Hash.blake256ripemd160(this.toBuffer());
};

/**
 * Will return an address for the public key
 *
 * @param {String|Network=} network - Which network should the address be for
 * @returns {Address} An address generated from the public key
 */
PublicKey.prototype.toAddress = function(network) {
  var Address = require('./address');
  return Address.fromPublicKey(this, network || this.network);
};

/**
 * Will output the PublicKey to a DER encoded hex string
 *
 * @returns {string} A DER hex encoded string
 */
PublicKey.prototype.toString = function() {
  return this.toDER().toString('hex');
};

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Public key
 */
PublicKey.prototype.inspect = function() {
  return '<PublicKey: ' + this.toString() +
    (this.compressed ? '' : ', uncompressed') + '>';
};


module.exports = PublicKey;
