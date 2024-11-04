'use strict';

var bitcore = module.exports;


// main bitcoin library
bitcore.Address = require('./lib/address');
bitcore.Networks = require('./lib/networks');
bitcore.PrivateKey = require('./lib/privatekey');
bitcore.Script = require('./lib/script');
bitcore.Transaction = require('./lib/transaction');
