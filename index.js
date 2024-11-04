'use strict';

var bitcore = module.exports;

// module information
bitcore.version = 'v' + require('./package.json').version;

// errors thrown by the library
bitcore.errors = require('./lib/errors');

// main bitcoin library
bitcore.Address = require('./lib/address');
bitcore.Networks = require('./lib/networks');
bitcore.Opcode = require('./lib/opcode');
bitcore.PrivateKey = require('./lib/privatekey');
bitcore.PublicKey = require('./lib/publickey');
bitcore.Script = require('./lib/script');
bitcore.Transaction = require('./lib/transaction');
bitcore.Unit = require('./lib/unit');
