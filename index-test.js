'use strict';

// Index file for testing

var bitcore = module.exports;

Object.assign(bitcore, require('./index.js'))

// module information
bitcore.version = 'v' + require('./package.json').version;

// crypto
bitcore.crypto = {};
bitcore.crypto.BN = require('./lib/crypto/bn').BN;
bitcore.crypto.ECDSA = require('./lib/crypto/ecdsa');
bitcore.crypto.Hash = require('./lib/crypto/hash');
bitcore.crypto.Random = require('./lib/crypto/random');
bitcore.crypto.Signature = require('./lib/crypto/signature');

// encoding
bitcore.encoding = {};
bitcore.encoding.Base58 = require('./lib/encoding/base58');
bitcore.encoding.Base58Check = require('./lib/encoding/base58check');
bitcore.encoding.BufferReader = require('./lib/encoding/bufferreader');
bitcore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
bitcore.encoding.Varint = require('./lib/encoding/varint');

// utilities
bitcore.util = {};
bitcore.util.buffer = require('./lib/util/buffer');
bitcore.util.js = require('./lib/util/js');
bitcore.util.preconditions = require('./lib/util/preconditions');

// main bitcoin library
bitcore.Opcode = require('./lib/opcode');
bitcore.PublicKey = require('./lib/publickey');
bitcore.Unit = require('./lib/unit');

// Internal usage, exposed for testing/advanced tweaking
bitcore.Transaction.sighash = require('./lib/transaction/sighash');

// errors thrown by the library
bitcore.errors = require('./lib/errors');