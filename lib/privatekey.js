'use strict';

var _ = require('lodash');
var Address = require('./address');
var Base58 = require('./encoding/base58');
var Hash = require('./crypto/hash')
const BNUtil = require('./crypto/bn');
const { BN } = BNUtil;
var JSUtil = require('./util/js');
var Networks = require('./networks');
var PublicKey = require('./publickey');
var Random = require('./crypto/random');
var $ = require('./util/preconditions');

const N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

/**
 * Instantiate a PrivateKey from a BN, Buffer and WIF.
 *
 * @example
 * ```javascript
 * // generate a new random key
 * var key = PrivateKey();
 *
 * // get the associated address
 * var address = key.toAddress();
 *
 * // encode into wallet export format
 * var exported = key.toWIF();
 *
 * // instantiate from the exported (and saved) private key
 * var imported = PrivateKey.fromWIF(exported);
 * ```
 *
 * @param {string} data - The encoded data in various formats
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {PrivateKey} A new valid instance of an PrivateKey
 * @constructor
 */
function PrivateKey(data, network) {
  /* jshint maxstatements: 20 */
  /* jshint maxcomplexity: 8 */

  if (!(this instanceof PrivateKey)) {
    return new PrivateKey(data, network);
  }
  if (data instanceof PrivateKey) {
    return data;
  }

  var info = this._classifyArguments(data, network);

  // validation
  if (!info.bn || info.bn.cmp(new BN(0)) === 0){
    throw new TypeError('Number can not be equal to zero, undefined, null or false');
  }
  if (!BNUtil.lt(info.bn, N)) {
    throw new TypeError('Number must be less than N');
  }
  if (typeof(info.network) === 'undefined') {
    throw new TypeError('Must specify the network ("livenet" or "testnet")');
  }

  JSUtil.defineImmutable(this, {
    bn: info.bn,
    compressed: info.compressed,
    network: info.network
  });

  Object.defineProperty(this, 'publicKey', {
    configurable: false,
    enumerable: true,
    get: this.toPublicKey.bind(this)
  });

  return this;

};

/**
 * Internal helper to instantiate PrivateKey internal `info` object from
 * different kinds of arguments passed to the constructor.
 *
 * @param {*} data
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @return {Object}
 */
PrivateKey.prototype._classifyArguments = function(data, network) {
  /* jshint maxcomplexity: 10 */
  var info = {
    compressed: true,
    network: network ? Networks.get(network) : Networks.defaultNetwork
  };

  // detect type of data
  if (_.isUndefined(data) || _.isNull(data)){
    info.bn = PrivateKey._getRandomBN();
  } else if (data instanceof BN) {
    info.bn = data;
  } else if (data instanceof Buffer || data instanceof Uint8Array) {
    info = PrivateKey._transformBuffer(data, network);
  } else if (data.bn && data.network){
    info = PrivateKey._transformObject(data);
  } else if (!network && Networks.get(data)) {
    info.bn = PrivateKey._getRandomBN();
    info.network = Networks.get(data);
  } else if (typeof(data) === 'string'){
    if (JSUtil.isHexa(data)) {
      info.bn = new BN(Buffer.from(data, 'hex'));
    } else {
      info = PrivateKey._transformWIF(data, network);
    }
  } else {
    throw new TypeError('First argument is an unrecognized data type.');
  }
  return info;
};

/**
 * Internal function to get a random Big Number (BN)
 *
 * @returns {BN} A new randomly generated BN
 * @private
 */
PrivateKey._getRandomBN = function(){
  var condition;
  var bn;
  do {
    var privbuf = Random.getRandomBuffer(32);
    bn = BNUtil.fromBuffer(privbuf);
    condition = BNUtil.lt(bn, N);
  } while (!condition);
  return bn;
};

/**
 * Internal function to transform a WIF Buffer into a private key
 *
 * @param {Buffer} buf - An WIF string
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformBuffer = function(buf, network) {

  var info = {};

  if (buf.length === 32) {
    return PrivateKey._transformBNBuffer(buf, network);
  }
  var networkBuffer = buf.slice(0,2).readUInt16BE(0);
  info.network = Networks.get(networkBuffer, 'privatekey');

  if (!info.network) {
    throw new Error('Invalid network');
  }

  if (network && info.network !== Networks.get(network)) {
    throw new TypeError('Private key network mismatch');
  }

  if (buf.length === 2 + 1 + 32 + 1 && buf[2] === 0 && buf[2 + 1 + 32 + 1 - 1] === 1) {
    info.compressed = true;
  } else if (buf.length === 2 + 1 + 32) {
    info.compressed = false;
  } else {
    throw new Error('Length of buffer must be 35 (uncompressed) or 36 (compressed)');
  }

  info.bn = BNUtil.fromBuffer(buf.slice(2 + 1, 2 + 1 + 32));

  return info;
};

/**
 * Internal function to transform a BN buffer into a private key
 *
 * @param {Buffer} buf
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name
 * @returns {object} an Object with keys: bn, network, and compressed
 * @private
 */
PrivateKey._transformBNBuffer = function(buf, network) {
  var info = {};
  info.network = Networks.get(network) || Networks.defaultNetwork;
  info.bn = BNUtil.fromBuffer(buf);
  info.compressed = false;
  return info;
};

/**
 * Internal function to transform a WIF string into a private key
 *
 * @param {string} buf - An WIF string
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformWIF = function(str, network) {
  // return PrivateKey._transformBuffer(Base58Check.decode(str), network);

  const buf = Base58.decode(str)
  const chksum = Hash.blake256(buf.slice(0, 2 + 1 + 32)).slice(0, 4)
  if (!chksum.equals(buf.slice(-4))) throw new Error('Invalid checksum')

  if (buf[2] !== 0) throw new Error('Only ECTypeSecp256k1 supported now')

  const wifNetwork = buf.readUInt16BE(0)
  if (network !== undefined && wifNetwork !== network) throw new Error('Invalid network')

  return {
    network: wifNetwork,
    bn: BNUtil.fromBuffer(buf.slice(2 + 1, 2 + 1 + 32)),
    compressed: true
  }
};

/**
 * Instantiate a PrivateKey from a Buffer with the DER or WIF representation
 *
 * @param {Buffer} arg
 * @param {Network} network
 * @return {PrivateKey}
 */
PrivateKey.fromBuffer = function(arg, network) {
  return new PrivateKey(arg, network);
};

/**
 * Internal function to transform a JSON string on plain object into a private key
 * return this.
 *
 * @param {string} json - A JSON string or plain object
 * @returns {Object} An object with keys: bn, network and compressed
 * @private
 */
PrivateKey._transformObject = function(json) {
  var bn = new BN(json.bn, 'hex');
  var network = Networks.get(json.network);
  return {
    bn: bn,
    network: network,
    compressed: json.compressed
  };
};

/**
 * Instantiate a PrivateKey from a WIF string
 *
 * @param {string} str - The WIF encoded private key string
 * @returns {PrivateKey} A new valid instance of PrivateKey
 */
PrivateKey.fromString = PrivateKey.fromWIF = function(str) {
  $.checkArgument(_.isString(str), 'First argument is expected to be a string.');
  return new PrivateKey(str);
};

/**
 * Instantiate a PrivateKey from a plain JavaScript object
 *
 * @param {Object} obj - The output from privateKey.toObject()
 */
PrivateKey.fromObject = function(obj) {
  $.checkArgument(_.isObject(obj), 'First argument is expected to be an object.');
  return new PrivateKey(obj);
};

/**
 * Instantiate a PrivateKey from random bytes
 *
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {PrivateKey} A new valid instance of PrivateKey
 */
PrivateKey.fromRandom = function(network) {
  var bn = PrivateKey._getRandomBN();
  return new PrivateKey(bn, network);
};

/**
 * Check if there would be any errors when initializing a PrivateKey
 *
 * @param {string} data - The encoded data in various formats
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {null|Error} An error if exists
 */

PrivateKey.getValidationError = function(data, network) {
  var error;
  try {
    /* jshint nonew: false */
    new PrivateKey(data, network);
  } catch (e) {
    error = e;
  }
  return error;
};

/**
 * Check if the parameters are valid
 *
 * @param {string} data - The encoded data in various formats
 * @param {string=} network - Either "livenet" or "testnet"
 * @returns {Boolean} If the private key is would be valid
 */
PrivateKey.isValid = function(data, network){
  if (!data) {
    return false;
  }
  return !PrivateKey.getValidationError(data, network);
};

/**
 * Will output the PrivateKey encoded as hex string
 *
 * @returns {string}
 */
PrivateKey.prototype.toString = function() {
  return this.toBuffer().toString('hex');
};

/**
 * Will output the PrivateKey to a WIF string
 *
 * @returns {string} A WIP representation of the private key
 */
PrivateKey.prototype.toWIF = function() {
  // var network = this.network;
  // var compressed = this.compressed;

  // var buf;
  // var networkBuffer = Buffer.alloc(3);
  // networkBuffer.writeUInt16BE(network.privatekey);
  // networkBuffer[2] = 0; // ECTypeSecp256k1
  // if (compressed) {
  //   buf = Buffer.concat([networkBuffer,
  //                        BNUtil.toBuffer(this.bn, {size: 32}),
  //                        Buffer.from([0x01])]);
  // } else {
  //   buf = Buffer.concat([networkBuffer,
  //                        BNUtil.toBuffer(this.bn, {size: 32})]);
  // }

  // return Base58Check.encode(buf);

  const buf = Buffer.alloc(2 + 1 + 32 + 4).fill(0)
  buf.writeUInt16BE(this.network.privatekey, 0)
  buf.writeUInt8(0, 2)
  BNUtil.toBuffer(this.bn, { size: 32 }).copy(buf, 2 + 1)
  Hash.blake256(buf.slice(0, 2 + 1 + 32)).slice(0, 4).copy(buf, 2 + 1 + 32)
  return Base58.encode(buf)
};

/**
 * Will return the private key as a BN instance
 *
 * @returns {BN} A BN instance of the private key
 */
PrivateKey.prototype.toBigNumber = function(){
  return this.bn;
};

/**
 * Will return the private key as a BN buffer
 *
 * @returns {Buffer} A buffer of the private key
 */
PrivateKey.prototype.toBuffer = function(){
  return BNUtil.toBuffer(this.bn);
};

/**
 * Will return the corresponding public key
 *
 * @returns {PublicKey} A public key generated from the private key
 */
PrivateKey.prototype.toPublicKey = function(){
  if (!this._pubkey) {
    this._pubkey = PublicKey.fromPrivateKey(this);
  }
  return this._pubkey;
};

/**
 * Will return an address for the private key
 * @param {Network=} network - optional parameter specifying
 * the desired network for the address
 *
 * @returns {Address} An address generated from the private key
 */
PrivateKey.prototype.toAddress = function(network) {
  var pubkey = this.toPublicKey();
  return Address.fromPublicKey(pubkey, network || this.network);
};

/**
 * @returns {Object} A plain object representation
 */
PrivateKey.prototype.toObject = PrivateKey.prototype.toJSON = function toObject() {
  return {
    bn: this.bn.toString('hex'),
    compressed: this.compressed,
    network: this.network.toString()
  };
};

/**
 * Will return a string formatted for the console
 *
 * @returns {string} Private key
 */
PrivateKey.prototype.inspect = function() {
  var uncompressed = !this.compressed ? ', uncompressed' : '';
  return '<PrivateKey: ' + this.toString() + ', network: ' + this.network + uncompressed + '>';
};

module.exports = PrivateKey;
