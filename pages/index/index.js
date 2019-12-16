var Buffer = require('buffer/').Buffer  // note: the trailing slash is important!
var argon2 = require('argon2-wasm-pro')  // note: the trailing slash is important!
var crypto3 = require('browser-crypto')  // note: the trailing slash is important!
const bs58check = require("bs58check");
function encodeAccount(pub) {
  console.log('encodeAccount收到', pub)
  let version = Buffer.from([0x01]);
  let v_pub = Buffer.concat([version, pub]);
  console.log("encodeAccount返回" + bs58check.encode(v_pub));
  return "czr_";
}


console.log('crypto3', crypto3)
//index.js
//获取应用实例
const app = getApp()
var fs = wx.getFileSystemManager()
console.log('fs', fs);
fs.writeFileSync(`${wx.env.USER_DATA_PATH}/hello2.txt`, 'hello, Anbang', 'utf8')

var files = fs.readdirSync(wx.env.USER_DATA_PATH);
var fileInfo = fs.readFileSync(`${wx.env.USER_DATA_PATH}/hello.txt`, 'utf8');
console.log('files', files);
console.log('文件内容：', fileInfo);
//本地用户文件


// 强随机开始
var create = (function () {
  function F() { };

  return function (obj) {
    var subtype;

    F.prototype = obj;

    subtype = new F();

    F.prototype = null;

    return subtype;
  };
}())
var Base = (function () {
  return {
    /**
     * Creates a new object that inherits from this object.
     *
     * @param {Object} overrides Properties to copy into the new object.
     *
     * @return {Object} The new object.
     *
     * @static
     *
     * @example
     *
     *     var MyType = CryptoJS.lib.Base.extend({
     *         field: 'value',
     *
     *         method: function () {
     *         }
     *     });
     */
    extend: function (overrides) {
      // Spawn
      var subtype = create(this);

      // Augment
      if (overrides) {
        subtype.mixIn(overrides);
      }

      // Create default initializer
      if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
        subtype.init = function () {
          subtype.$super.init.apply(this, arguments);
        };
      }

      // Initializer's prototype is the subtype object
      subtype.init.prototype = subtype;

      // Reference supertype
      subtype.$super = this;

      return subtype;
    },

    /**
     * Extends this object and runs the init method.
     * Arguments to create() will be passed to init().
     *
     * @return {Object} The new object.
     *
     * @static
     *
     * @example
     *
     *     var instance = MyType.create();
     */
    create: function () {
      var instance = this.extend();
      instance.init.apply(instance, arguments);

      return instance;
    },

    /**
     * Initializes a newly created object.
     * Override this method to add some logic when your objects are created.
     *
     * @example
     *
     *     var MyType = CryptoJS.lib.Base.extend({
     *         init: function () {
     *             // ...
     *         }
     *     });
     */
    init: function () {
    },

    /**
     * Copies properties into this object.
     *
     * @param {Object} properties The properties to mix in.
     *
     * @example
     *
     *     MyType.mixIn({
     *         field: 'value'
     *     });
     */
    mixIn: function (properties) {
      for (var propertyName in properties) {
        if (properties.hasOwnProperty(propertyName)) {
          this[propertyName] = properties[propertyName];
        }
      }

      // IE won't copy toString using the loop above
      if (properties.hasOwnProperty('toString')) {
        this.toString = properties.toString;
      }
    },

    /**
     * Creates a copy of this object.
     *
     * @return {Object} The clone.
     *
     * @example
     *
     *     var clone = instance.clone();
     */
    clone: function () {
      return this.init.prototype.extend(this);
    }
  };
}());
var crypto = {
  WordArray: Base.extend({
    /**
     * Initializes a newly created word array.
     *
     * @param {Array} words (Optional) An array of 32-bit words.
     * @param {number} sigBytes (Optional) The number of significant bytes in the words.
     *
     * @example
     *
     *     var wordArray = CryptoJS.lib.WordArray.create();
     *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
     *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
     */
    init: function (words, sigBytes) {
      words = this.words = words || [];

      if (sigBytes != undefined) {
        this.sigBytes = sigBytes;
      } else {
        this.sigBytes = words.length * 4;
      }
    },

    /**
     * Converts this word array to a string.
     *
     * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
     *
     * @return {string} The stringified word array.
     *
     * @example
     *
     *     var string = wordArray + '';
     *     var string = wordArray.toString();
     *     var string = wordArray.toString(CryptoJS.enc.Utf8);
     */
    toString: function (encoder) {
      return (encoder || Hex).stringify(this);
    },

    /**
     * Concatenates a word array to this word array.
     *
     * @param {WordArray} wordArray The word array to append.
     *
     * @return {WordArray} This word array.
     *
     * @example
     *
     *     wordArray1.concat(wordArray2);
     */
    concat: function (wordArray) {
      // Shortcuts
      var thisWords = this.words;
      var thatWords = wordArray.words;
      var thisSigBytes = this.sigBytes;
      var thatSigBytes = wordArray.sigBytes;

      // Clamp excess bits
      this.clamp();

      // Concat
      if (thisSigBytes % 4) {
        // Copy one byte at a time
        for (var i = 0; i < thatSigBytes; i++) {
          var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
          thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
        }
      } else {
        // Copy one word at a time
        for (var i = 0; i < thatSigBytes; i += 4) {
          thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
        }
      }
      this.sigBytes += thatSigBytes;

      // Chainable
      return this;
    },

    /**
     * Removes insignificant bits.
     *
     * @example
     *
     *     wordArray.clamp();
     */
    clamp: function () {
      // Shortcuts
      var words = this.words;
      var sigBytes = this.sigBytes;

      // Clamp
      words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
      words.length = Math.ceil(sigBytes / 4);
    },

    /**
     * Creates a copy of this word array.
     *
     * @return {WordArray} The clone.
     *
     * @example
     *
     *     var clone = wordArray.clone();
     */
    clone: function () {
      var clone = Base.clone.call(this);
      clone.words = this.words.slice(0);

      return clone;
    },

    /**
     * Creates a word array filled with random bytes.
     *
     * @param {number} nBytes The number of random bytes to generate.
     *
     * @return {WordArray} The random word array.
     *
     * @static
     *
     * @example
     *
     *     var wordArray = CryptoJS.lib.WordArray.random(16);
     */
    random: function (nBytes) {
      var words = [];

      var r = (function (m_w) {
        var m_w = m_w;
        var m_z = 0x3ade68b1;
        var mask = 0xffffffff;

        return function () {
          m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
          m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
          var result = ((m_z << 0x10) + m_w) & mask;
          result /= 0x100000000;
          result += 0.5;
          return result * (Math.random() > .5 ? 1 : -1);
        }
      });

      for (var i = 0, rcache; i < nBytes; i += 4) {
        var _r = r((rcache || Math.random()) * 0x100000000);

        rcache = _r() * 0x3ade67b7;
        words.push((_r() * 0x100000000) | 0);
      }

      return new WordArray.init(words, nBytes);
    }
  }),
  randomBytes: function (nBytes) {
    var words = [];
    var r = (function (m_w) {
      var m_w = m_w;
      var m_z = 0x3ade68b1;
      var mask = 0xffffffff;
      return function () {
        m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
        m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
        var result = ((m_z << 0x10) + m_w) & mask;
        result /= 0x100000000;
        result += 0.5;
        return result * (Math.random() > .5 ? 1 : -1);
      }
    });

    for (var i = 0, rcache; i < nBytes; i++) {
      // console.log("i", i)
      var _r = r((rcache || Math.random()) * 0x100000000);

      rcache = _r() * 0x3ade67b7;
      words.push((_r() * 0x100000000) | 0);
    }
    return Buffer.from((new crypto.WordArray.init(words, nBytes)).words);
    // let res = (new crypto.WordArray.init(words, nBytes)).words;
    // return (new Uint8Array(res).buffer);
    // return (new crypto.WordArray.init(words, nBytes)).words;
  }
}
var RandomArray = crypto.randomBytes(32);
console.log("Tartget RandomArray", RandomArray, RandomArray.length)
// 强随机结束

// var crypto2 =require('crypto-browserify')
// console.log(crypto2.createCipheriv)
// var aes = require('browserify-cipher')
// console.log(aes.createCipheriv)


// ed25519
var __ed25519wasm = (function () {
  var _scriptDir = typeof document !== 'undefined' && document.currentScript ? document.currentScript.src : undefined;
  return (
    function (__ed25519wasm) {
      __ed25519wasm = __ed25519wasm || {};

      var b;
      b || (b = typeof __ed25519wasm !== 'undefined' ? __ed25519wasm : {});
      var g = {}, l;
      for (l in b) b.hasOwnProperty(l) && (g[l] = b[l]);
      b.arguments = [];
      b.thisProgram = "./this.program";
      b.quit = function (a, c) {
        throw c;
      };
      b.preRun = [];
      b.postRun = [];
      var m = !1, n = !1, p = !1, q = !1, r = !1;
      m = "object" === typeof window;
      n = "function" === typeof importScripts;
      p = (q = "object" === typeof process && "object" === typeof process.versions && "string" === typeof process.versions.node) && !m && !n;
      r = !m && !p && !n;
      var t = "", u, v;
      if (p) {
        t = __dirname + "/";
        var w, x;
        u = function (a, c) {
          w || (w = require("fs"));
          x || (x = require("path"));
          a = x.normalize(a);
          a = w.readFileSync(a);
          return c ? a : a.toString()
        };
        v = function (a) {
          a = u(a, !0);
          a.buffer || (a = new Uint8Array(a));
          a.buffer || y("Assertion failed: undefined");
          return a
        };
        1 < process.argv.length && (b.thisProgram = process.argv[1].replace(/\\/g, "/"));
        b.arguments = process.argv.slice(2);
        process.on("uncaughtException", function (a) {
          // if (!(a instanceof z)) throw a;
        });
        process.on("unhandledRejection", y);
        b.quit = function (a) {
          process.exit(a)
        };
        b.inspect = function () {
          return "[Emscripten Module object]"
        }
      } else if (r) "undefined" != typeof read && (u = function (a) {
        return read(a)
      }), v = function (a) {
        if ("function" === typeof readbuffer) return new Uint8Array(readbuffer(a));
        a = read(a, "binary");
        "object" === typeof a || y("Assertion failed: undefined");
        return a
      }, "undefined" != typeof scriptArgs ? b.arguments = scriptArgs : "undefined" != typeof arguments && (b.arguments = arguments), "function" === typeof quit && (b.quit = function (a) {
        quit(a)
      }); else if (m || n) n ? t = self.location.href : document.currentScript &&
        (t = document.currentScript.src), _scriptDir && (t = _scriptDir), 0 !== t.indexOf("blob:") ? t = t.substr(0, t.lastIndexOf("/") + 1) : t = "", u = function (a) {
          var c = new XMLHttpRequest;
          c.open("GET", a, !1);
          c.send(null);
          return c.responseText
        }, n && (v = function (a) {
          var c = new XMLHttpRequest;
          c.open("GET", a, !1);
          c.responseType = "arraybuffer";
          c.send(null);
          return new Uint8Array(c.response)
        });
      var A = b.print || ("undefined" !== typeof console ? console.log.bind(console) : "undefined" !== typeof print ? print : null),
        B = b.printErr || ("undefined" !== typeof printErr ? printErr : "undefined" !== typeof console && console.warn.bind(console) || A);
      for (l in g) g.hasOwnProperty(l) && (b[l] = g[l]);
      g = void 0;
      var C = {
        "f64-rem": function (a, c) {
          return a % c
        }, "debugger": function () {
          debugger
        }
      };
      "object" !== typeof WebAssembly && B("no native wasm support detected");
      var E, F = !1;
      "undefined" !== typeof TextDecoder && new TextDecoder("utf8");
      "undefined" !== typeof TextDecoder && new TextDecoder("utf-16le");
      var buffer, G, H, I, J = b.TOTAL_MEMORY || 16777216;
      5242880 > J && B("TOTAL_MEMORY should be larger than TOTAL_STACK, was " + J + "! (TOTAL_STACK=5242880)");
      b.wasmMemory ? E = b.wasmMemory : E = new WebAssembly.Memory({ initial: J / 65536, maximum: J / 65536 });
      E && (buffer = E.buffer);
      J = buffer.byteLength;
      b.HEAP8 = G = new Int8Array(buffer);
      b.HEAP16 = new Int16Array(buffer);
      b.HEAP32 = I = new Int32Array(buffer);
      b.HEAPU8 = H = new Uint8Array(buffer);
      b.HEAPU16 = new Uint16Array(buffer);
      b.HEAPU32 = new Uint32Array(buffer);
      b.HEAPF32 = new Float32Array(buffer);
      b.HEAPF64 = new Float64Array(buffer);
      I[8796] = 5278096;

      function K(a) {
        for (; 0 < a.length;) {
          var c = a.shift();
          if ("function" == typeof c) c(); else {
            var h = c.m;
            "number" === typeof h ? void 0 === c.l ? b.dynCall_v(h) : b.dynCall_vi(h, c.l) : h(void 0 === c.l ? null : c.l)
          }
        }
      }

      var L = [], M = [], N = [], O = [];

      function aa() {
        var a = b.preRun.shift();
        L.unshift(a)
      }

      var P = 0, Q = null, R = null;
      b.preloadedImages = {};
      b.preloadedAudios = {};

      // 兼容浏览器和node环境的 base解码--开始
      var lookup = []
      var revLookup = []
      var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array
      var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
      for (var i = 0, len = code.length; i < len; ++i) {
        lookup[i] = code[i]
        revLookup[code.charCodeAt(i)] = i
      }
      // Support decoding URL-safe base64 strings, as Node.js does.
      // See: https://en.wikipedia.org/wiki/Base64#URL_applications
      revLookup['-'.charCodeAt(0)] = 62
      revLookup['_'.charCodeAt(0)] = 63


      //111111
      function getLens(b64) {
        var len = b64.length

        if (len % 4 > 0) {
          throw new Error('Invalid string. Length must be a multiple of 4')
        }

        // Trim off extra bytes after placeholder bytes are found
        // See: https://github.com/beatgammit/base64-js/issues/42
        var validLen = b64.indexOf('=')
        if (validLen === -1) validLen = len

        var placeHoldersLen = validLen === len
          ? 0
          : 4 - (validLen % 4)

        return [validLen, placeHoldersLen]
      }

      //111111
      function _byteLength(b64, validLen, placeHoldersLen) {
        return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
      }

      function toByteArray(b64) {
        var tmp
        var lens = getLens(b64)
        var validLen = lens[0]
        var placeHoldersLen = lens[1]

        var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

        var curByte = 0

        // if there are placeholders, only get up to the last complete 4 chars
        var len = placeHoldersLen > 0
          ? validLen - 4
          : validLen

        for (var i = 0; i < len; i += 4) {
          tmp =
            (revLookup[b64.charCodeAt(i)] << 18) |
            (revLookup[b64.charCodeAt(i + 1)] << 12) |
            (revLookup[b64.charCodeAt(i + 2)] << 6) |
            revLookup[b64.charCodeAt(i + 3)]
          arr[curByte++] = (tmp >> 16) & 0xFF
          arr[curByte++] = (tmp >> 8) & 0xFF
          arr[curByte++] = tmp & 0xFF
        }

        if (placeHoldersLen === 2) {
          tmp =
            (revLookup[b64.charCodeAt(i)] << 2) |
            (revLookup[b64.charCodeAt(i + 1)] >> 4)
          arr[curByte++] = tmp & 0xFF
        }

        if (placeHoldersLen === 1) {
          tmp =
            (revLookup[b64.charCodeAt(i)] << 10) |
            (revLookup[b64.charCodeAt(i + 1)] << 4) |
            (revLookup[b64.charCodeAt(i + 2)] >> 2)
          arr[curByte++] = (tmp >> 8) & 0xFF
          arr[curByte++] = tmp & 0xFF
        }

        return arr
      }
      // 兼容浏览器和node环境的 base解码--结束


      let wasmBase64 = "AGFzbQEAAAABSQxgAX8AYAABf2ABfwF/YAJ/fwBgA39/fwBgAX8BfmADf39/AX5gBH9/f38AYAJ/fwF/YAN/f38Bf2AFf39/f38AYAR/f39/AX8COwYDZW52AWIAAANlbnYBYwACA2VudgFkAAIDZW52AWUAAQNlbnYBYQN/AANlbnYGbWVtb3J5AgGAAoACAzMyBAMGBQQEAwkECAMEAgADAwMDAgADBAADBAMEAwMDAwICAwACCAsKAwcECAMEBAcDAwMGCAF/AUGQkwILBxUFAWYALQFnACoBaAApAWkAJgFqACcKntwBMsUJAg1/KX4gAigCBCIDrCEQIAIoAggiBKwhGCACKAIMIgWsIRsgAigCECIGrCEdIAIoAhQiB6whHyACKAIYIgisISYgAigCHCIJrCEtIAIoAiAiCqwhMCABKAIEIgusISAgASgCDCIMrCEhIAEoAhQiDawhIiABKAIcIg6sISMgASgCJCIPrCEkIA9BAXSsIicgA0ETbKx+IAEoAgCsIhEgAigCAKwiEn58IAEoAiCsIhMgBEETbKwiLn58IA5BAXSsIiggBUETbKwiKX58IAEoAhisIhQgBkETbKwiJX58IA1BAXSsIiogB0ETbKwiHn58IAEoAhCsIhUgCEETbKwiHH58IAxBAXSsIisgCUETbKwiGX58IApBE2ysIhcgASgCCKwiFn58IAtBAXSsIiwgAigCJCIBQRNsrCIafnwhMSAQIBR+IBIgI358IBggIn58IBUgG358IB0gIX58IBYgH358ICAgJn58IBEgLX58IBcgJH58IBMgGn58IBAgKn4gEiAUfnwgFSAYfnwgGyArfnwgFiAdfnwgHyAsfnwgESAmfnwgGSAnfnwgEyAXfnwgGiAofnwgECAVfiASICJ+fCAYICF+fCAWIBt+fCAdICB+fCARIB9+fCAcICR+fCATIBl+fCAXICN+fCAUIBp+fCAQICt+IBIgFX58IBYgGH58IBsgLH58IBEgHX58IB4gJ358IBMgHH58IBkgKH58IBQgF358IBogKn58Ii9CgICAEHwiM0Iah3wiNEKAgIAIfCI1QhmHfCI2QoCAgBB8IjdCGod8ITIgLyAzQoCAgGCDfSASICF+IBAgFn58IBggIH58IBEgG358ICQgJX58IBMgHn58IBwgI358IBQgGX58IBcgIn58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KAIgIhEgASgCIHNxIRIgAiAAKAIkIhMgASgCJHNxIRQgACAAKAIAIhUgAiAVIAEoAgBzcXM2AgAgACADIARzNgIEIAAgBSAGczYCCCAAIAcgCHM2AgwgACAJIApzNgIQIAAgCyAMczYCFCAAIA0gDnM2AhggACAPIBBzNgIcIAAgESASczYCICAAIBMgFHM2AiQL3hMCCH8ffiAALAAAIAAsAAEgAEECaiICLAAAEAZC////AIMhEwJ+IAIQB0IFiEL///8AgyEnIAAsAAUgACwABiAAQQdqIgMsAAAQBkICiEL///8AgyEfIAMQB0IHiEL///8AgyEgIABBCmoiBxAHQgSIQv///wCDIRkgACwADSAALAAOIABBD2oiBCwAABAGQgGIQv///wCDISEgBBAHQgaIQv///wCDIRQgACwAEiAALAATIAAsABQQBkIDiEL///8AgyEaIAAsABUgACwAFiAAQRdqIgUsAAAQBkL///8AgyEVIAUQB0IFiEL///8AgyEbIAAsABogACwAGyAAQRxqIgYsAAAQBkICiEL///8AgyEWIAYQB0IHiEL///8AgyEcIABBH2oiCBAHQgSIQv///wCDIRAgACwAIiAALAAjIABBJGoiASwAABAGQgGIQv///wCDIREgARAHQgaIQv///wCDIRICfiAALAAnIAAsACggACwAKRAGQgOIQv///wCDISYgACwAKiAALAArIABBLGoiASwAABAGQv///wCDIQwgARAHQgWIQv///wCDIR0gACwALyAALAAwIABBMWoiASwAABAGQgKIQv///wCDIQkgARAHQgeIQv///wCDIQogAEE0ahAHQgSIQv///wCDIQsgACwANyAALAA4IABBOWoiASwAABAGQgGIQv///wCDIQ0gARAHQgaIQv///wCDIQ4gAEE8ahAHQgOIIg9Cg6FWfiAMfCEMIAtCg6FWfiARfCANQtGrCH58IA9C5/YnfnwgDkLTjEN+fCAKQoOhVn4gEHwgC0LRqwh+fCANQtOMQ358IA9CmNocfnwgDkLn9id+fCIeQoCAQH0iIkIVh3whESAmCyAPQtGrCH58IA5Cg6FWfnwgDUKDoVZ+IBJ8IA9C04xDfnwgDkLRqwh+fCIjQoCAQH0iJEIVh3whEiAdIAxCgIBAfSIXQhWHfCEQIB4gIkKAgIB/g30gCUKD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ACABKAIIayEDQQAgASgCDGshBEEAIAEoAhBrIQVBACABKAIUayEGQQAgASgCGGshB0EAIAEoAhxrIQhBACABKAIgayEJQQAgASgCJGshCiAAQQAgASgCAGs2AgAgACACNgIEIAAgAzYCCCAAIAQ2AgwgACAFNgIQIAAgBjYCFCAAIAc2AhggACAINgIcIAAgCTYCICAAIAo2AiQL4wEBAn8jASEBIwFBIGokASABIAAQHSABLAAfIAEsAB4gASwAHSABLAAcIAEsABsgASwAGiABLAAZIAEsABggASwAFyABLAAWIAEsABUgASwAFCABLAATIAEsABIgASwAESABLAAQIAEsAA8gASwADiABLAANIAEsAAwgASwACyABLAAKIAEsAAkgASwACCABLAAHIAEsAAYgASwABSABLAAEIAEsAAMgASwAAiABLAAAIAEsAAFycnJycnJycnJycnJycnJycnJycnJycnJycnJycnJyQf8BcUEARyECIAEkASACCyUBAn8jASEBIwFBIGokASABIAAQHSABLAAAQQFxIQIgASQBIAILmQQBFX4CfiABEAchFiABLAAEIAEsAAUgASwABhAGQgaGIQcgASwAByABLAAIIAEsAAkQBkIFhiEDIAEsAAogASwACyABLAAMEAZCA4YhCCABLAANIAEsAA4gASwADxAGQgKGIQQgAUEQahAHIQkgASwAFCABLAAVIAEsABYQBkIHhiEFIAEsABcgASwAGCABLAAZEAZCBYYhCiABLAAaIAEsABsgASwAHBAGQgSGIQYgFgtCACABLAAdIAEsAB4gASwAHxAGQgKGQvz//w+DIgtCgICACHwiDEIZiH1CE4N8Ig1CgICAEHwhAiADIAdCgICACHwiDkIZh3wiD0KAgIAQfCEDIAQgCEKAgIAIfCIQQhmHfCIRQoCAgBB8IQQgBSAJQoCAgAh8IhJCGYd8IhNCgICAEHwhBSAGIApCgICACHwiFEIZh3wiFUKAgIAQfCEGIAAgDSACQoCAgOAPg30+AgAgACAHIA5CgICA8A+DfSACQhqIfD4CBCAAIA8gA0KAgIDgD4N9PgIIIAAgCCAQQoCAgPAPg30gA0IaiHw+AgwgACARIARCgICA4A+DfT4CECAAIAkgEkKAgIDwD4N9IARCGoh8PgIUIAAgEyAFQoCAgOAPg30+Ahgg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ciAALAAUIAEsABRzciAALAAVIAEsABVzciAALAAWIAEsABZzciAALAAXIAEsABdzciAALAAYIAEsABhzciAALAAZIAEsABlzciAALAAaIAEsABpzciAALAAbIAEsABtzciAALAAcIAEsABxzciAALAAdIAEsAB1zciAALAAeIAEsAB5zciAALAAfIAEsAB9zckH/AXFFC5cBAQZ/IwEhBCMBQdAEaiQBIARBIGohBiAEQeAAaiEFIARBqANqIQcgBEGwAmohCCAALQA/QR9KBH9BAAUgByADEC4Ef0EABSAFEBYaIAUgAEEgEAsaIAUgA0EgEAsaIAUgASACEAsaIAUgBhAUIAYQGiAIIAYgByAAQSBqEDIgBCAIEBsgBCAAEChBAEcLCyEJIAQkASAJC4wBAQN/IwEhBSMBQfADaiQBIAVBgAFqIgYQFhogBiAEQSBqQSAQCxogBiABIAIQCxogBiAFEBQgBRAaIAVB0AJqIgcgBRAfIAAgBxAbIAYQFhogBiAAQSAQCxogBiADQSAQCxogBiABIAIQCxogBiAFQUBrIgEQFCABEBogAEEgaiABIAQgBRAsIAUkAQsuAQF/IwEhAiMBQdABaiQBIAIQFkUEQCACIABBIBALRQRAIAIgARAUCwsgAiQBC/cgAgF/N34gASwAACABLAABIAFBAmoiBCwAABAGQv///wCDIQUgBBAHQgWIQv///wCDIQYgASwABSABLAAGIAFBB2oiBCwAABAGQgKIQv///wCDIQ4gBBAHQgeIQv///wCDIQ8gAUEKahAHQgSIQv///wCDIQogASwADSABLAAOIAFBD2oiBCwAABAGQgGIQv///wCDIQcgBBAHQgaIQv///wCDIQsgASwAEiABLAATIAEsABQQBkIDiEL///8AgyENIAEsABUgASwAFiABQRdqIgQsAAAQBkL///8AgyEIIAQQB0IFiEL///8AgyEQIAEsABogASwAGyABQRxqIgEsAAAQBkICiEL///8AgyEMIAEQB0IHiCEJIAIsAAAgAiwAASACQQJqIgEsAAAQBkL///8AgyEYIAEQB0IFiEL///8AgyEZIAIsAAUgAiwABiACQQdqIgEsAAAQBkICiEL///8AgyEbIAEQB0IHiEL///8AgyEcIAJBCmoQB0IEiEL///8AgyEaIAIsAA0gAiwADiACQQ9qIgEsAAAQBkIBiEL///8AgyEVIAEQB0IGiEL///8AgyEWIAIsABIgAiwAEyACLAAUEAZCA4hC////AIMhESACLAAVIAIsABYgAkEXaiIBLAAAEAZC////AIMhEyABEAdCBYhC////AIMhFCACLAAaIAIsABsgAkEcaiIBLAAAEAZCAohC////AIMhEiABEAdCB4ghFyADLAAAIAMsAAEgA0ECaiIBLAAAEAZC////AIMhHSABEAdCBYhC////AIMhHiADLAAFIAMsAAYgA0EHaiIBLAAAEAZCAohC////AIMhMSABEAdCB4hC////AIMhMiADQQpqEAdCBIhC////AIMhMyADLAANIAMsAA4gA0EPaiIBLAAAEAZCAYhC////AIMhNCABEAdCBohC////AIMhKiADLAASIAMsABMgAywAFBAGQgOIQv///wCDITUgAywAFSADLAAWIANBF2oiASwAABAGQv///wCDISsgARAHQgWIQv///wCDISwgECAZfiAMIBh+fCAIIBt+fCANIBx+fCALIBp+fCAHIBV+fCAKIBZ+fCAOIBN+fCAPIBF+fCAGIBR+fCAFIBJ+fCADLAAaIAMsABsgA0EcaiIBLAAAEAZCAohC////AIN8Ii1CgIBAfSElIAwgFH4gCSATfnwgECASfnwgCCAXfnwgDCATfiAJIBF+fCAQIBR+fCAIIBJ+fCANIBd+fCIfQoCAQH0iJkIVh3whISAMIBd+IAkgEn58IAwgEn4gCSAUfnwgECAXfnwiIkKAgEB9IiRCFYh8ISAgCSAXfiInQoCAQH0iKEIViCEjIAUgGX4gBiAYfnwgHnwgHSAFIBh+fCI2QoCAQH0iN0IViHwiOEKAgEB9ITAgHyAmQoCAgH+DfSAQIBN+IAkgFn58IAwgEX58IAggFH58IA0gEn58IAsgF358IAwgFn4gCSAVfnwgCCATfnwgECARfnwgDSAUfnwgCyASfnwgByAXfnwiLkKAgEB9IilCFYd8IjlCgIBAfSI6QhWHfCEdICIgJEKAgID///////8Ag30gIUKAgEB9Ii9CFYd8IR4gJyAoQoCAgP///////wCDfSAgQoCAQH0iIkIViHwhHyAjQoOhVn4gLnwgKUKAgIB/g30gDCAVfiAJIBp+fCAQIBZ+fCANIBN+fCAIIBF+fCALIBR+fCAHIBJ+fCAK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"

      let wasmBuffer = toByteArray(wasmBase64);
      function getBinaryPromise() {
        return new Promise(function (resolve, reject) {
          resolve(wasmBuffer)
        })
      }

      function ca(a) {
        function c(a) {
          b.asm = a.exports;
          P--;
          b.monitorRunDependencies && b.monitorRunDependencies(P);
          0 == P && (null !== Q && (clearInterval(Q), Q = null), R && (a = R, R = null, a()))
        }

        function h(a) {
          c(a.instance)
        }

        function k(a) {
          return getBinaryPromise().then(function (a) {
            return WebAssembly.instantiate(a, e)
          }).then(a, function (a) {
            B("failed to asynchronously prepare wasm: " + a);
            y(a)
          })
        }

        var e = { env: a, global: { NaN: NaN, Infinity: Infinity }, "global.Math": Math, asm2wasm: C };
        P++;
        b.monitorRunDependencies && b.monitorRunDependencies(P);
        if (b.instantiateWasm) try {
          return b.instantiateWasm(e,
            c)
        } catch (f) {
          return B("Module.instantiateWasm callback failed with error: " + f), !1
        }

        (function () {
          if (b.wasmBinary || "function" !== typeof WebAssembly.instantiateStreaming || "function" !== typeof fetch) return k(h);
          return WebAssembly.instantiateStreaming(wasmBase64, e).then(h, function (a) {
            B("wasm streaming compile failed: " + a);
            B("falling back to ArrayBuffer instantiation");
            k(h)
          })
        })();
        return {}
      }

      b.asm = function (a, c) {
        c.memory = E;
        c.table = new WebAssembly.Table({ initial: 0, maximum: 0, element: "anyfunc" });
        c.__memory_base = 1024;
        c.__table_base = 0;

        return ca(c)
      };

      function W() {
        y("OOM")
      }

      var X = b.asm({}, {
        b: function (a) {
          b.___errno_location && (I[b.___errno_location() >> 2] = a);
          return a
        }, e: function () {
          return G.length
        }, d: function (a) {
          W(a)
        }, c: W, a: 35184
      }, buffer);
      b.asm = X;
      b._ed25519_create_keypair = function () {
        return b.asm.f.apply(null, arguments)
      };
      b._ed25519_sign = function () {
        return b.asm.g.apply(null, arguments)
      };
      b._ed25519_verify = function () {
        return b.asm.h.apply(null, arguments)
      };
      var Y = b._free = function () {
        return b.asm.i.apply(null, arguments)
      }, da = b._malloc = function () {
        return b.asm.j.apply(null, arguments)
      };
      b.asm = X;
      b.then = function (a) {
        if (b.calledRun) a(b); else {
          var c = b.onRuntimeInitialized;
          b.onRuntimeInitialized = function () {
            c && c();
            a(b)
          }
        }
        return b
      };

      function z(a) {
        this.name = "ExitStatus";
        this.message = "Program terminated with exit(" + a + ")";
        this.status = a
      }

      z.prototype = Error();
      z.prototype.constructor = z;
      R = function ea() {
        b.calledRun || Z();
        b.calledRun || (R = ea)
      };

      function Z() {
        function a() {
          if (!b.calledRun && (b.calledRun = !0, !F)) {
            K(M);
            K(N);
            if (b.onRuntimeInitialized) b.onRuntimeInitialized();
            if (b.postRun) for ("function" == typeof b.postRun && (b.postRun = [b.postRun]); b.postRun.length;) {
              var a = b.postRun.shift();
              O.unshift(a)
            }
            K(O)
          }
        }

        if (!(0 < P)) {
          if (b.preRun) for ("function" == typeof b.preRun && (b.preRun = [b.preRun]); b.preRun.length;) aa();
          K(L);
          0 < P || b.calledRun || (b.setStatus ? (b.setStatus("Running..."), setTimeout(function () {
            setTimeout(function () {
              b.setStatus("")
            }, 1);
            a()
          }, 1)) : a())
        }
      }

      b.run = Z;

      function y(a) {
        if (b.onAbort) b.onAbort(a);
        A(a);
        B(a);
        F = !0;
        throw "abort(" + a + "). Build with -s ASSERTIONS=1 for more info.";
      }

      b.abort = y;
      if (b.preInit) for ("function" == typeof b.preInit && (b.preInit = [b.preInit]); 0 < b.preInit.length;) b.preInit.pop()();
      b.noExitRuntime = !0;
      Z();
      (function () {
        function a(a) {
          if (a && a.buffer instanceof ArrayBuffer) a = new Uint8Array(a.buffer, a.byteOffset, a.byteLength); else if ("string" === typeof a) {
            for (var c = a.length, e = new Uint8Array(c + 1), D = 0; D < c; ++D) e[D] = a.charCodeAt(D);
            return e
          }
          return a
        }

        function c(e, f) {
          var d = new Number(e);
          d.length = f;
          d.get = function (a) {
            a = a || Uint8Array;
            return (new a(buffer, d, f / a.BYTES_PER_ELEMENT)).slice()
          };
          d.dereference = function (a) {
            a = a || 4;
            return c(d.get(Uint32Array)[0], a)
          };
          d.set = function (c) {
            c = a(c);
            if (c.length > f) throw RangeError("invalid array length");
            H.set(c, d)
          };
          d.free = function () {
            Y(d);
            k.splice(k.indexOf(d), 1)
          };
          k.push(d);
          return d
        }

        function h(e, f) {
          f = a(f);
          0 === e && (e = f.length);
          var d = c(da(e), e);
          void 0 !== f ? (d.set(f), f.length < e && H.fill(0, d + f.length, d + e)) : H.fill(0, d, d + e);
          return d
        }

        var k = [];
        b.createPointer = c;
        b.allocatePointer = function (a) {
          a && (a = Uint32Array.of(a));
          return h(4, a)
        };
        b.allocateBytes = h;
        b.freeBytes = function () {
          for (var a = 0, c = k.length; a < c; ++a) Y(k[a]);
          k = []
        }
      })();


      return __ed25519wasm
    }
  );
})();


let random_bytes = function (size) {
  // let array;
  // array = new Uint8Array(size);
  // crypto.getRandomValues(array);
  // return array;
  return crypto.randomBytes(size)
};
console.log('ed25519用的', random_bytes(32))
function Wrapper(lib) {
  let allocate, free;
  lib = lib();
  allocate = lib['allocateBytes'];
  free = lib['freeBytes'];

  function createSeed() {
    return random_bytes(32);
  }

  function createKeyPair(seed) {
    let publicKey, secretKey;
    if (!(seed instanceof Uint8Array)) {
      throw new Error('not Uint8Array!');
    }
    seed = allocate(0, seed);
    publicKey = allocate(32);
    secretKey = allocate(64);
    lib['_ed25519_create_keypair'](publicKey, secretKey, seed);
    publicKey = publicKey['get']();
    secretKey = secretKey['get']();
    free();
    return {
      publicKey: publicKey,
      secretKey: secretKey
    };
  }

  function sign(message, publicKey, secretKey) {
    let signature;
    if (!(message instanceof Uint8Array && publicKey instanceof Uint8Array && secretKey instanceof Uint8Array)) {
      throw new Error('not Uint8Arrays!');
    }
    message = allocate(0, message);
    publicKey = allocate(0, publicKey);
    secretKey = allocate(0, secretKey);
    signature = allocate(64);
    lib['_ed25519_sign'](signature, message, message['length'], publicKey, secretKey);
    signature = signature['get']();
    free();
    return signature;
  }

  function verify(signature, message, publicKey) {
    let result;
    if (!(signature instanceof Uint8Array && message instanceof Uint8Array && publicKey instanceof Uint8Array)) {
      throw new Error('not Uint8Arrays!');
    }
    message = allocate(0, message);
    publicKey = allocate(0, publicKey);
    signature = allocate(0, signature);
    result = lib['_ed25519_verify'](signature, message, message['length'], publicKey) === 1;
    free();
    return result;
  }
  return {
    'ready': lib['then'],
    'createSeed': createSeed,
    'createKeyPair': createKeyPair,
    'sign': sign,
    'verify': verify
  };
}

var ed25519 = Wrapper(__ed25519wasm);
console.log(ed25519)
ed25519.ready(function () {
  const prv = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");
  const keys = ed25519.createKeyPair(prv)
  console.log("3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29", Buffer.from(keys.publicKey.buffer).toString('hex').toUpperCase())
  const keys2 = ed25519.createKeyPair(RandomArray)
  console.log(keys2, Buffer.from(keys2.publicKey.buffer).toString('hex').toUpperCase())
})
// ed25519.ready(function () {
//   console.log('********************')
//   const keys2 = ed25519.createKeyPair(RandomArray)
//   console.log(keys2)
// })
// ed25519

// account


/* 封装Accounts类 */
let Accounts = function (dev) {
  if (dev) {
    //如果是测试环境
    this.COSTNUM = 256;
  } else {
    this.COSTNUM = 16 * 1024;
  }
};
async function createAccount(password, COSTNUM) {
  let kdf_salt = crypto.randomBytes(16);
  let iv = crypto.randomBytes(16);
  let privateKey = crypto.randomBytes(32);


  //测试的
  // let kdf_salt    = Buffer.from("AF8460A7D28A396C62D6C51620B87789", "hex");
  // let iv          = Buffer.from("A695DDC35ED9F3183A09FED1E6D92083", "hex");
  // let privateKey  = Buffer.from("5E844EE4D2E26920F8B0C4B7846929057CFCE48BF40BA269B173648999630053", "hex");

  // console.log("私钥",privateKey.toString('hex'));

  //password hashing
  let kdf_option = {
    pass: password.toString(),
    salt: kdf_salt,
    type: argon2.argon2id,
    time: 1,
    mem: COSTNUM,
    parallelism: 1,
    hashLen: 32,

    // raw: true,
    // version: 0x13
  };
  try {
    let derivePwd = await argon2.hash(kdf_option);
    //加密私钥
    // console.log("argon2",crypto)
    console.log("derivePwd", derivePwd)
    console.log('-------')
    console.log(Buffer.from(derivePwd.hash.buffer), iv)
    console.log('-------')
    // var cryptoAesCtr = require("crypto-aes-ctr");

    let cipher = crypto3.createCipheriv("aes-256-ctr", Buffer.from(derivePwd.hash.buffer), iv);//加密方法aes-256-ctr
    // let cipher = argon3.createStream(Buffer.from(derivePwd.hash.buffer), iv);//加密方法aes-256-ctr
    console.log('cipher', cipher)
    let ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
    let promise = new Promise(function (resolve, reject) {
      try {
        // 生成公钥
        ed25519.ready(function () {
          const keypair = ed25519.createKeyPair(privateKey)
          let publicKey = Buffer.from(keypair.publicKey.buffer);

          //clear privateKey for security, any better methed?
          // crypto.randomFillSync(Buffer.from(derivePwd.hash.buffer));
          // crypto.randomFillSync(privateKey);

          let accFile = {
            account: encodeAccount(publicKey),
            kdf_salt: kdf_salt.toString('hex').toUpperCase(),
            iv: iv.toString('hex').toUpperCase(),
            ciphertext: ciphertext.toString('hex').toUpperCase()
          }
          resolve(accFile)
        })
      } catch (e) {
        reject(e)
      }
    });
    return promise;
  } catch (err) {
    throw err;
  }

}
Accounts.prototype.create = function (password) {
  return createAccount(password, this.COSTNUM);
};

var accounts = new Accounts(false)

accounts.create(123456).then(res => {
  console.log("创建账号收到结果\n", res);//res.account
}).catch(err => {
  console.log("err===>", err);
});

Page({
  data: {
    motto: `${files}---${fileInfo}`,
    userInfo: {},
    hasUserInfo: false,
    canIUse: wx.canIUse('button.open-type.getUserInfo')
  },
  //事件处理函数
  bindViewTap: function () {
    wx.navigateTo({
      url: '../logs/logs'
    })
  },
  onLoad: function () {
    if (app.globalData.userInfo) {
      this.setData({
        userInfo: app.globalData.userInfo,
        hasUserInfo: true
      })
    } else if (this.data.canIUse) {
      // 由于 getUserInfo 是网络请求，可能会在 Page.onLoad 之后才返回
      // 所以此处加入 callback 以防止这种情况
      app.userInfoReadyCallback = res => {
        this.setData({
          userInfo: res.userInfo,
          hasUserInfo: true
        })
      }
    } else {
      // 在没有 open-type=getUserInfo 版本的兼容处理
      wx.getUserInfo({
        success: res => {
          app.globalData.userInfo = res.userInfo
          this.setData({
            userInfo: res.userInfo,
            hasUserInfo: true
          })
        }
      })
    }
  },
  getUserInfo: function (e) {
    console.log(e)
    app.globalData.userInfo = e.detail.userInfo
    this.setData({
      userInfo: e.detail.userInfo,
      hasUserInfo: true
    })
  }
})
