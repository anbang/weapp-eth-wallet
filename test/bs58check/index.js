module.exports = (function () {
  var __MODS__ = {};
  var __DEFINE__ = function (modId, func, req) { var m = { exports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
  var __REQUIRE__ = function (modId, source) { if (!__MODS__[modId]) return require(source); if (!__MODS__[modId].status) { var m = { exports: {} }; __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); if (typeof m.exports === "object") { __MODS__[modId].m.exports.__proto__ = m.exports.__proto__; Object.keys(m.exports).forEach(function (k) { __MODS__[modId].m.exports[k] = m.exports[k]; var desp = Object.getOwnPropertyDescriptor(m.exports, k); if (desp && desp.configurable) Object.defineProperty(m.exports, k, { set: function (val) { __MODS__[modId].m.exports[k] = val; }, get: function () { return __MODS__[modId].m.exports[k]; } }); }); if (m.exports.__esModule) Object.defineProperty(__MODS__[modId].m.exports, "__esModule", { value: true }); } else { __MODS__[modId].m.exports = m.exports; } } return __MODS__[modId].m.exports; };
  var __REQUIRE_WILDCARD__ = function (obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
  var __REQUIRE_DEFAULT__ = function (obj) { return obj && obj.__esModule ? obj.default : obj; };
  __DEFINE__(1576496545563, function (require, module, exports) {


    var createHash = require('sha.js')
    // var hash = require('sha.js')
    var bs58checkBase = require('./base')
    // var hash = new sha1.sha256();

    // SHA256(SHA256(buffer))
    function sha256x2(buffer) {
      // hash.sha256().update('abc').digest('hex')
      // // var tmp = hash.sha256().update(buffer).digest('hex');
      // var tmp = hash.update(buffer).digest();
      // return hash.update(tmp).digest()
      // // var tmp = hash.sha256().update(buffer).digest();
      // // return hash.sha256().update(tmp).digest()

      var tmp = createHash('sha256').update(buffer).digest()

      console.log('sha256x2 tmp', (tmp))
      console.log('sha256x2 buffer1', (createHash('sha256').update(tmp).digest()))
      //   126, 215, 173, 95, 35, 93, 9, .... 0, 229, 187, 70, 209, 36, 243,  232,  114 

      return createHash('sha256').update(tmp).digest()

    }
    // console.log('sha256x2',sha256x2)
    module.exports = bs58checkBase(sha256x2)

  }, function (modId) { var map = { "./base": 1576496545564 }; return __REQUIRE__(map[modId], modId); })
  __DEFINE__(1576496545564, function (require, module, exports) {


    var base58 = require('bs58')
    var Buffer = require('safe-buffer').Buffer

    module.exports = function (checksumFn) {
      // Encode a buffer as a base58-check encoded string
      function encode(payload) {
        console.log('payload.payload', payload)
        var checksum = checksumFn(payload)

        return base58.encode(Buffer.concat([
          payload,
          checksum
        ], payload.length + 4))
      }

      function decodeRaw(buffer) {
        var payload = buffer.slice(0, -4)
        var checksum = buffer.slice(-4)
        var newChecksum = checksumFn(payload)

        if (checksum[0] ^ newChecksum[0] |
          checksum[1] ^ newChecksum[1] |
          checksum[2] ^ newChecksum[2] |
          checksum[3] ^ newChecksum[3]) return

        return payload
      }

      // Decode a base58-check encoded string to a buffer, no result if checksum is wrong
      function decodeUnsafe(string) {
        var buffer = base58.decodeUnsafe(string)
        if (!buffer) return

        return decodeRaw(buffer)
      }

      function decode(string) {
        var buffer = base58.decode(string)
        var payload = decodeRaw(buffer, checksumFn)
        if (!payload) throw new Error('Invalid checksum')
        return payload
      }

      return {
        encode: encode,
        decode: decode,
        decodeUnsafe: decodeUnsafe
      }
    }

  }, function (modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
  return __REQUIRE__(1576496545563);
})()
  //# sourceMappingURL=index.js.map