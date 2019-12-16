'use strict'

// var createHash = require('sha.js')
var hash = require('sha.js')
var bs58checkBase = require('./base')

// SHA256(SHA256(buffer))
function sha256x2(buffer) {
  hash.sha256().update('abc').digest('hex')

  // var tmp = hash.sha256().update(buffer).digest('hex');
  var tmp = hash.sha256().update(buffer).digest();
  return ash.sha256().update(tmp).digest()
}
console.log('sha256x2',sha256x2)


module.exports = bs58checkBase(sha256x2)
