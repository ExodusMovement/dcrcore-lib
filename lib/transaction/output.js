'use strict';

var _ = require('lodash');
const BNUtil = require('../crypto/bn');
const { BN } = BNUtil;
var bufferUtil = require('../util/buffer');
var JSUtil = require('../util/js');
var BufferWriter = require('../encoding/bufferwriter');
var Script = require('../script');
var $ = require('../util/preconditions');
var errors = require('../errors');

var MAX_SAFE_INTEGER = 0x1fffffffffffff;

function Output(args) {
  if (!(this instanceof Output)) {
    return new Output(args);
  }
  if (_.isObject(args)) {
    this.atoms = args.atoms;
    if (bufferUtil.isBuffer(args.script)) {
      this._scriptBuffer = args.script;
    } else {
      var script;
      if (_.isString(args.script) && JSUtil.isHexa(args.script)) {
        script = Buffer.from(args.script, 'hex');
      } else {
        script = args.script;
      }
      this.setScript(script);
    }
  } else {
    throw new TypeError('Unrecognized argument for Output');
  }
}

Object.defineProperty(Output.prototype, 'script', {
  configurable: false,
  enumerable: true,
  get: function() {
    if (this._script) {
      return this._script;
    } else {
      this.setScriptFromBuffer(this._scriptBuffer);
      return this._script;
    }

  }
});

Object.defineProperty(Output.prototype, 'atoms', {
  configurable: false,
  enumerable: true,
  get: function() {
    return this._atoms;
  },
  set: function(num) {
    if (num instanceof BN) {
      this._atomsBN = num;
      this._atoms = BNUtil.toNumber(num);
    } else if (_.isString(num)) {
      this._atoms = parseInt(num);
      this._atomsBN = BNUtil.fromNumber(this._atoms);
    } else {
      $.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output atoms is not a natural number'
      );
      this._atomsBN = BNUtil.fromNumber(num);
      this._atoms = num;
    }
    $.checkState(
      JSUtil.isNaturalNumber(this._atoms),
      'Output atoms is not a natural number'
    );
  }
});

Output.prototype.invalidSatoshis = function() {
  if (this._atoms > MAX_SAFE_INTEGER) {
    return 'transaction txout atoms greater than max safe integer';
  }
  if (this._atoms !== BNUtil.toNumber(this._atomsBN)) {
    return 'transaction txout atoms has corrupted value';
  }
  if (this._atoms < 0) {
    return 'transaction txout negative';
  }
  return false;
};

Output.prototype.toObject = Output.prototype.toJSON = function toObject() {
  var obj = {
    atoms: this.atoms
  };
  obj.script = this._scriptBuffer.toString('hex');
  return obj;
};

Output.fromObject = function(data) {
  return new Output(data);
};

Output.prototype.setScriptFromBuffer = function(buffer) {
  this._scriptBuffer = buffer;
  try {
    this._script = Script.fromBuffer(this._scriptBuffer);
    this._script._isOutput = true;
  } catch(e) {
    if (e instanceof errors.Script.InvalidBuffer) {
      this._script = null;
    } else {
      throw e;
    }
  }
};

Output.prototype.setScript = function(script) {
  if (script instanceof Script) {
    this._scriptBuffer = script.toBuffer();
    this._script = script;
    this._script._isOutput = true;
  } else if (_.isString(script)) {
    this._script = Script.fromString(script);
    this._scriptBuffer = this._script.toBuffer();
    this._script._isOutput = true;
  } else if (bufferUtil.isBuffer(script)) {
    this.setScriptFromBuffer(script);
  } else {
    throw new TypeError('Invalid argument type: script');
  }
  return this;
};

Output.prototype.inspect = function() {
  var scriptStr;
  if (this.script) {
    scriptStr = this.script.inspect();
  } else {
    scriptStr = this._scriptBuffer.toString('hex');
  }
  return '<Output (' + this.atoms + ' sats) ' + scriptStr + '>';
};

Output.fromBufferReader = function(br) {
  var obj = {};
  obj.atoms = br.readUInt64LEBN();
  obj.vers = br.readUInt16LE();
  var size = br.readVarintNum();
  if (size !== 0) {
    obj.script = br.read(size);
  } else {
    obj.script = Buffer.alloc(0);
  }
  return new Output(obj);
};

Output.prototype.toBufferWriter = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  writer.writeUInt64LEBN(this._atomsBN);
  writer.writeUInt16LE(0x00);
  var script = this._scriptBuffer;
  writer.writeVarintNum(script.length);
  writer.write(script);
  return writer;
};

module.exports = Output;
