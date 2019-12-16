module.exports = (function() {
var __MODS__ = {};
var Buffer = require('buffer/').Buffer  // note: the trailing slash is important!

var __DEFINE__ = function(modId, func, req) { var m = { exports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = { exports: {} }; __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); if(typeof m.exports === "object") { __MODS__[modId].m.exports.__proto__ = m.exports.__proto__; Object.keys(m.exports).forEach(function(k) { __MODS__[modId].m.exports[k] = m.exports[k]; var desp = Object.getOwnPropertyDescriptor(m.exports, k); if(desp && desp.configurable) Object.defineProperty(m.exports, k, { set: function(val) { __MODS__[modId].m.exports[k] = val; }, get: function() { return __MODS__[modId].m.exports[k]; } }); }); if(m.exports.__esModule) Object.defineProperty(__MODS__[modId].m.exports, "__esModule", { value: true }); } else { __MODS__[modId].m.exports = m.exports; } } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1576466087054, function(require, module, exports) {
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.argon2 = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    const global = typeof self !== 'undefined' ? self : this;

    /**
     * @enum
     */
    const ArgonType = {
        argon2d: 0,
        argon2i: 1,
        argon2id: 2
    };

    // 加载Module
    function loadModule(mem) {
        if (loadModule._promise) {
            return loadModule._promise;
        }
        if (loadModule._module) {
            return Promise.resolve(loadModule._module);
        }
        let promise = loadWasmModule().then(
            Module =>
                new Promise(resolve => {
                    Module.postRun.push(() => resolve(Module));
                })
        );
        loadModule._promise = promise;
        return promise.then(Module => {
            loadModule._module = Module;
            delete loadModule._promise;
            return Module;
        });
    }

    function loadWasmModule() {
        // if (global.loadArgon2WasmModule) {
        //     return global.loadArgon2WasmModule();
        // }
        return Promise.resolve(require('./dist/argon2.js'));
    }

    //分配数组
    function allocateArray(Module, strOrArr) {
        const arr =
            strOrArr instanceof Uint8Array || strOrArr instanceof Array
                ? strOrArr
                : encodeUtf8(strOrArr);
        const nullTerminatedArray = new Uint8Array([...arr, 0]);
        return Module.allocate(nullTerminatedArray, 'i8', Module.ALLOC_NORMAL);
    }

    function encodeUtf8(str) {
        if (typeof TextEncoder === 'function') {
            return new TextEncoder().encode(str);
        } else if (typeof Buffer === 'function') {
            return Buffer.from(str);
        } else {
            throw new Error("Don't know how to decode UTF8");
        }
    }

    /**
     * Argon2 hash
     * @param {string|Uint8Array} params.pass - password string
     * @param {string|Uint8Array} params.salt - salt string
     * @param {number} [params.time=1] - the number of iterations
     * @param {number} [params.mem=1024] - used memory, in KiB
     * @param {number} [params.hashLen=24] - desired hash length
     * @param {number} [params.parallelism=1] - desired parallelism
     * @param {number} [params.type=argon2.argon2d] - hash type:
     *      argon2.argon2d
     *      argon2.argon2i
     *      argon2.argon2id
     *
     * @return Promise
     *
     * @example
     *  argon2.hash({ pass: 'password', salt: 'somesalt' })
     *      .then(h => console.log(h.hash, h.hashHex, h.encoded))
     *      .catch(e => console.error(e.message, e.code))
     */
    function argon2Hash(params) {
        const mCost = params.mem || 1024;
        return loadModule(mCost).then(Module => {
            const tCost = params.time || 1;
            const parallelism = params.parallelism || 1;
            const pwd = allocateArray(Module, params.pass);
            const pwdlen = params.pass.length;
            const salt = allocateArray(Module, params.salt);
            const saltlen = params.salt.length;
            const hash = Module.allocate(
                new Array(params.hashLen || 24),
                'i8',
                Module.ALLOC_NORMAL
            );
            const hashlen = params.hashLen || 24;
            const encoded = Module.allocate(
                new Array(512),
                'i8',
                Module.ALLOC_NORMAL
            );
            const encodedlen = 512;
            const argon2Type = params.type || ArgonType.argon2d;
            const version = 0x13;
            let err;
            let res;
            try {
                res = Module._argon2_hash(
                    tCost,
                    mCost,
                    parallelism,
                    pwd,
                    pwdlen,
                    salt,
                    saltlen,
                    hash,
                    hashlen,
                    encoded,
                    encodedlen,
                    argon2Type,
                    version
                );
            } catch (e) {
                err = e;
            }
            let result;
            if (res === 0 && !err) {
                let hashStr = '';
                const hashArr = new Uint8Array(hashlen);
                for (let i = 0; i < hashlen; i++) {
                    const byte = Module.HEAP8[hash + i];
                    hashArr[i] = byte;
                    hashStr += ('0' + (0xff & byte).toString(16)).slice(-2);
                }
                const encodedStr = Module.UTF8ToString(encoded);
                result = {
                    hash: hashArr,
                    hashHex: hashStr,
                    encoded: encodedStr
                };
            } else {
                try {
                    if (!err) {
                        err = Module.UTF8ToString(
                            Module._argon2_error_message(res)
                        );
                    }
                } catch (e) { }
                result = { message: err, code: res };
            }
            try {
                Module._free(pwd);
                Module._free(salt);
                Module._free(hash);
                Module._free(encoded);
            } catch (e) { }
            if (err) {
                throw result;
            } else {
                return result;
            }
        });
    }

    /**
     * Argon2 verify function
     * @param {string} params.pass - password string
     * @param {string|Uint8Array} params.encoded - encoded hash
     * @param {number} [params.type=argon2.argon2d] - hash type:
     *      argon2.argon2d
     *      argon2.argon2i
     *      argon2.argon2id
     *
     * @returns Promise
     *
     * @example
     *  argon2.verify({ pass: 'password', encoded: 'encoded-hash' })
     *      .then(() => console.log('OK'))
     *      .catch(e => console.error(e.message, e.code))
     */
    function argon2Verify(params) {
        return loadModule().then(Module => {
            const pwd = allocateArray(Module, params.pass);
            const pwdlen = params.pass.length;
            const enc = allocateArray(Module, params.encoded);
            let argon2Type = params.type;
            if (argon2Type === undefined) {
                let typeStr = params.encoded.split('$')[1];
                if (typeStr) {
                    typeStr = typeStr.replace('a', 'A');
                    argon2Type = ArgonType[typeStr] || ArgonType.argon2d;
                }
            }
            let err;
            let res;
            try {
                res = Module._argon2_verify(enc, pwd, pwdlen, argon2Type);
            } catch (e) {
                err = e;
            }
            let result;
            if (res || err) {
                try {
                    if (!err) {
                        err = Module.UTF8ToString(
                            Module._argon2_error_message(res)
                        );
                    }
                } catch (e) { }
                result = { message: err, code: res };
            }
            try {
                Module._free(pwd);
                Module._free(enc);
            } catch (e) { }
            if (err) {
                throw result;
            } else {
                return result;
            }
        });
    }

    return {
        ...ArgonType,
        hash: argon2Hash,
        verify: argon2Verify
    };
});

}, function(modId) {var map = {"./dist/argon2.js":1576466087055}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1576466087055, function(require, module, exports) {
var Module = typeof self !== "undefined" && typeof self.Module !== "undefined" ? self.Module : {};
var moduleOverrides = {};
var key;
for (key in Module) {
    if (Module.hasOwnProperty(key)) {
        moduleOverrides[key] = Module[key]
    }
}
Module["arguments"] = [];
Module["thisProgram"] = "./this.program";
Module["quit"] = function (status, toThrow) {
    throw toThrow
};
Module["preRun"] = [];
Module["postRun"] = [];
var ENVIRONMENT_IS_WEB = false;
var ENVIRONMENT_IS_WORKER = false;
var ENVIRONMENT_IS_NODE = false;
var ENVIRONMENT_HAS_NODE = false;
var ENVIRONMENT_IS_SHELL = false;
ENVIRONMENT_IS_WEB = typeof window === "object";
ENVIRONMENT_IS_WORKER = typeof importScripts === "function";
ENVIRONMENT_HAS_NODE = typeof process === "object" && typeof process.versions === "object" && typeof process.versions.node === "string";
ENVIRONMENT_IS_NODE = ENVIRONMENT_HAS_NODE && !ENVIRONMENT_IS_WEB && !ENVIRONMENT_IS_WORKER;
ENVIRONMENT_IS_SHELL = !ENVIRONMENT_IS_WEB && !ENVIRONMENT_IS_NODE && !ENVIRONMENT_IS_WORKER;
var scriptDirectory = "";


if (ENVIRONMENT_IS_NODE) {
    scriptDirectory = __dirname + "/";

    if (process["argv"].length > 1) {
        Module["thisProgram"] = process["argv"][1].replace(/\\/g, "/")
    }
    Module["arguments"] = process["argv"].slice(2);
    if (typeof module !== "undefined") {
        module["exports"] = Module
    }
    process["on"]("uncaughtException", function (ex) {
        if (!(ex instanceof ExitStatus)) {
            throw ex
        }
    });
    process["on"]("unhandledRejection", abort);
    Module["quit"] = function (status) {
        process["exit"](status)
    };
    Module["inspect"] = function () {
        return "[Emscripten Module object]"
    }
} else if (ENVIRONMENT_IS_SHELL) {
    if (typeof scriptArgs != "undefined") {
        Module["arguments"] = scriptArgs
    } else if (typeof arguments != "undefined") {
        Module["arguments"] = arguments
    }
    if (typeof quit === "function") {
        Module["quit"] = function (status) {
            quit(status)
        }
    }
} else if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
    if (ENVIRONMENT_IS_WORKER) {
        scriptDirectory = self.location.href
    } else if (document.currentScript) {
        scriptDirectory = document.currentScript.src
    }
    if (scriptDirectory.indexOf("blob:") !== 0) {
        scriptDirectory = scriptDirectory.substr(0, scriptDirectory.lastIndexOf("/") + 1)
    } else {
        scriptDirectory = ""
    }
} else {
}
var out = Module["print"] || (typeof console !== "undefined" ? console.log.bind(console) : typeof print !== "undefined" ? print : null);
var err = Module["printErr"] || (typeof printErr !== "undefined" ? printErr : typeof console !== "undefined" && console.warn.bind(console) || out);
for (key in moduleOverrides) {
    if (moduleOverrides.hasOwnProperty(key)) {
        Module[key] = moduleOverrides[key]
    }
}
moduleOverrides = undefined;

function dynamicAlloc(size) {
    var ret = HEAP32[DYNAMICTOP_PTR >> 2];
    var end = ret + size + 15 & -16;
    if (end > _emscripten_get_heap_size()) {
        abort()
    }
    HEAP32[DYNAMICTOP_PTR >> 2] = end;
    return ret
}

function getNativeTypeSize(type) {
    switch (type) {
        case "i1":
        case "i8":
            return 1;
        case "i16":
            return 2;
        case "i32":
            return 4;
        case "i64":
            return 8;
        case "float":
            return 4;
        case "double":
            return 8;
        default: {
            if (type[type.length - 1] === "*") {
                return 4
            } else if (type[0] === "i") {
                var bits = parseInt(type.substr(1));
                assert(bits % 8 === 0, "getNativeTypeSize invalid bits " + bits + ", type " + type);
                return bits / 8
            } else {
                return 0
            }
        }
    }
}

var asm2wasmImports = {
    "f64-rem": function (x, y) {
        return x % y
    }, "debugger": function () {
        debugger
    }
};

if (typeof WebAssembly !== "object") {
    err("no native wasm support detected")
}

function setValue(ptr, value, type, noSafe) {
    type = type || "i8";
    if (type.charAt(type.length - 1) === "*") type = "i32";
    switch (type) {
        case "i1":
            HEAP8[ptr >> 0] = value;
            break;
        case "i8":
            HEAP8[ptr >> 0] = value;
            break;
        case "i16":
            HEAP16[ptr >> 1] = value;
            break;
        case "i32":
            HEAP32[ptr >> 2] = value;
            break;
        case "i64":
            tempI64 = [value >>> 0, (tempDouble = value, +Math_abs(tempDouble) >= 1 ? tempDouble > 0 ? (Math_min(+Math_floor(tempDouble / 4294967296), 4294967295) | 0) >>> 0 : ~~+Math_ceil((tempDouble - +(~~tempDouble >>> 0)) / 4294967296) >>> 0 : 0)], HEAP32[ptr >> 2] = tempI64[0], HEAP32[ptr + 4 >> 2] = tempI64[1];
            break;
        case "float":
            HEAPF32[ptr >> 2] = value;
            break;
        case "double":
            HEAPF64[ptr >> 3] = value;
            break;
        default:
            abort("invalid type for setValue: " + type)
    }
}

var wasmMemory;
var ABORT = false;

function assert(condition, text) {
    if (!condition) {
        abort("Assertion failed: " + text)
    }
}

var ALLOC_NORMAL = 0;
var ALLOC_NONE = 3;

function allocate(slab, types, allocator, ptr) {
    var zeroinit, size;
    if (typeof slab === "number") {
        zeroinit = true;
        size = slab
    } else {
        zeroinit = false;
        size = slab.length
    }
    var singleType = typeof types === "string" ? types : null;
    var ret;
    if (allocator == ALLOC_NONE) {
        ret = ptr
    } else {
        ret = [_malloc, stackAlloc, dynamicAlloc][allocator](Math.max(size, singleType ? 1 : types.length))
    }
    if (zeroinit) {
        var stop;
        ptr = ret;
        assert((ret & 3) == 0);
        stop = ret + (size & ~3);
        for (; ptr < stop; ptr += 4) {
            HEAP32[ptr >> 2] = 0
        }
        stop = ret + size;
        while (ptr < stop) {
            HEAP8[ptr++ >> 0] = 0
        }
        return ret
    }
    if (singleType === "i8") {
        if (slab.subarray || slab.slice) {
            HEAPU8.set(slab, ret)
        } else {
            HEAPU8.set(new Uint8Array(slab), ret)
        }
        return ret
    }
    var i = 0, type, typeSize, previousType;
    while (i < size) {
        var curr = slab[i];
        type = singleType || types[i];
        if (type === 0) {
            i++;
            continue
        }
        if (type == "i64") type = "i32";
        setValue(ret + i, curr, type);
        if (previousType !== type) {
            typeSize = getNativeTypeSize(type);
            previousType = type
        }
        i += typeSize
    }
    return ret
}

var UTF8Decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf8") : undefined;

function UTF8ArrayToString(u8Array, idx, maxBytesToRead) {
    var endIdx = idx + maxBytesToRead;
    var endPtr = idx;
    while (u8Array[endPtr] && !(endPtr >= endIdx))++endPtr;
    if (endPtr - idx > 16 && u8Array.subarray && UTF8Decoder) {
        return UTF8Decoder.decode(u8Array.subarray(idx, endPtr))
    } else {
        var str = "";
        while (idx < endPtr) {
            var u0 = u8Array[idx++];
            if (!(u0 & 128)) {
                str += String.fromCharCode(u0);
                continue
            }
            var u1 = u8Array[idx++] & 63;
            if ((u0 & 224) == 192) {
                str += String.fromCharCode((u0 & 31) << 6 | u1);
                continue
            }
            var u2 = u8Array[idx++] & 63;
            if ((u0 & 240) == 224) {
                u0 = (u0 & 15) << 12 | u1 << 6 | u2
            } else {
                u0 = (u0 & 7) << 18 | u1 << 12 | u2 << 6 | u8Array[idx++] & 63
            }
            if (u0 < 65536) {
                str += String.fromCharCode(u0)
            } else {
                var ch = u0 - 65536;
                str += String.fromCharCode(55296 | ch >> 10, 56320 | ch & 1023)
            }
        }
    }
    return str
}

function UTF8ToString(ptr, maxBytesToRead) {
    return ptr ? UTF8ArrayToString(HEAPU8, ptr, maxBytesToRead) : ""
}


var WASM_PAGE_SIZE = 65536;

function alignUp(x, multiple) {
    if (x % multiple > 0) {
        x += multiple - x % multiple
    }
    return x
}

var buffer, HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAPF64;

function updateGlobalBufferViews() {
    Module["HEAP8"] = HEAP8 = new Int8Array(buffer);
    Module["HEAP16"] = HEAP16 = new Int16Array(buffer);
    Module["HEAP32"] = HEAP32 = new Int32Array(buffer);
    Module["HEAPU8"] = HEAPU8 = new Uint8Array(buffer);
    Module["HEAPU16"] = HEAPU16 = new Uint16Array(buffer);
    Module["HEAPU32"] = HEAPU32 = new Uint32Array(buffer);
    Module["HEAPF32"] = HEAPF32 = new Float32Array(buffer);
    Module["HEAPF64"] = HEAPF64 = new Float64Array(buffer)
}

var DYNAMIC_BASE = 5248528, DYNAMICTOP_PTR = 5616;
var TOTAL_STACK = 5242880;
var INITIAL_TOTAL_MEMORY = Module["TOTAL_MEMORY"] || 16777216;
if (INITIAL_TOTAL_MEMORY < TOTAL_STACK) err("TOTAL_MEMORY should be larger than TOTAL_STACK, was " + INITIAL_TOTAL_MEMORY + "! (TOTAL_STACK=" + TOTAL_STACK + ")");
if (Module["wasmMemory"]) {
    wasmMemory = Module["wasmMemory"]
} else {
    wasmMemory = new WebAssembly.Memory({
        "initial": INITIAL_TOTAL_MEMORY / WASM_PAGE_SIZE,
        "maximum": 2147418112 / WASM_PAGE_SIZE
    })
}
if (wasmMemory) {
    buffer = wasmMemory.buffer
}
INITIAL_TOTAL_MEMORY = buffer.byteLength;
updateGlobalBufferViews();
HEAP32[DYNAMICTOP_PTR >> 2] = DYNAMIC_BASE;

function callRuntimeCallbacks(callbacks) {
    while (callbacks.length > 0) {
        var callback = callbacks.shift();
        if (typeof callback == "function") {
            callback();
            continue
        }
        var func = callback.func;
        if (typeof func === "number") {
            if (callback.arg === undefined) {
                Module["dynCall_v"](func)
            } else {
                Module["dynCall_vi"](func, callback.arg)
            }
        } else {
            func(callback.arg === undefined ? null : callback.arg)
        }
    }
}

var __ATPRERUN__ = [];
var __ATINIT__ = [];
var __ATMAIN__ = [];
var __ATPOSTRUN__ = [];

function preRun() {
    if (Module["preRun"]) {
        if (typeof Module["preRun"] == "function") Module["preRun"] = [Module["preRun"]];
        while (Module["preRun"].length) {
            addOnPreRun(Module["preRun"].shift())
        }
    }
    callRuntimeCallbacks(__ATPRERUN__)
}

function initRuntime() {
    callRuntimeCallbacks(__ATINIT__)
}

function preMain() {
    callRuntimeCallbacks(__ATMAIN__)
}


function postRun() {
    if (Module["postRun"]) {
        if (typeof Module["postRun"] == "function") Module["postRun"] = [Module["postRun"]];
        while (Module["postRun"].length) {
            addOnPostRun(Module["postRun"].shift())
        }
    }
    callRuntimeCallbacks(__ATPOSTRUN__)
}

function addOnPreRun(cb) {
    __ATPRERUN__.unshift(cb)
}

function addOnPostRun(cb) {
    __ATPOSTRUN__.unshift(cb)
}

var Math_abs = Math.abs;
var Math_ceil = Math.ceil;
var Math_floor = Math.floor;
var Math_min = Math.min;
var runDependencies = 0;
var runDependencyWatcher = null;
var dependenciesFulfilled = null;

function addRunDependency(id) {
    runDependencies++;
    if (Module["monitorRunDependencies"]) {
        Module["monitorRunDependencies"](runDependencies)
    }
}

function removeRunDependency(id) {
    runDependencies--;
    if (Module["monitorRunDependencies"]) {
        Module["monitorRunDependencies"](runDependencies)
    }
    if (runDependencies == 0) {
        if (runDependencyWatcher !== null) {
            clearInterval(runDependencyWatcher);
            runDependencyWatcher = null
        }
        if (dependenciesFulfilled) {
            var callback = dependenciesFulfilled;
            dependenciesFulfilled = null;
            callback()
        }
    }
}

Module["preloadedImages"] = {};
Module["preloadedAudios"] = {};


var loadModule = require('./sources.js');


function getBinary() {
    try {
        if (Module["wasmBinary"]) {
            return new Uint8Array(Module["wasmBinary"])
        }
        return loadModule
    } catch (err) {
        abort(err)
    }
}

function getBinaryPromise() {
    return new Promise(function (resolve, reject) {
        resolve(getBinary())
    })
}

function createWasm(env) {
    var info = {
        "env": env,
        "global": { "NaN": NaN, Infinity: Infinity },
        "global.Math": Math,
        "asm2wasm": asm2wasmImports
    };

    function receiveInstance(instance, module) {
        var exports = instance.exports;
        Module["asm"] = exports;
        removeRunDependency("wasm-instantiate")
    }

    addRunDependency("wasm-instantiate");

    function receiveInstantiatedSource(output) {
        receiveInstance(output["instance"])
    }

    function instantiateArrayBuffer(receiver) {
        return getBinaryPromise().then(function (binary) {
            var buf = new Buffer(31580);
            for (var i = 0; i < buf.length; ++i) {
                buf[i] = binary[i];
            }

            console.log('-----',buf)
            return WebAssembly.instantiate(buf, info)
        }).then(receiver, function (reason) {
            err("failed to asynchronously prepare wasm: " + reason);
            abort(reason)
        })
    }

    function instantiateAsync() {
        return instantiateArrayBuffer(receiveInstantiatedSource)
    }

    if (Module["instantiateWasm"]) {
        try {
            var exports = Module["instantiateWasm"](info, receiveInstance);
            return exports
        } catch (e) {
            err("Module.instantiateWasm callback failed with error: " + e);
            return false
        }
    }
    instantiateAsync();
    return {}
}

Module["asm"] = function (global, env, providedBuffer) {
    env["memory"] = wasmMemory;
    env["table"] = new WebAssembly.Table({ "initial": 11, "maximum": 11, "element": "anyfunc" });
    env["__memory_base"] = 1024;
    env["__table_base"] = 0;
    var exports = createWasm(env);
    return exports
};
var tempDouble;
var tempI64;

function _emscripten_get_heap_size() {
    return HEAP8.length
}

function _emscripten_memcpy_big(dest, src, num) {
    HEAPU8.set(HEAPU8.subarray(src, src + num), dest)
}

function _pthread_create() {
    return 11
}

function _exit(status) {
    exit(status)
}

function _pthread_exit(status) {
    _exit(status)
}

function _pthread_join() {
}

function ___setErrNo(value) {
    if (Module["___errno_location"]) HEAP32[Module["___errno_location"]() >> 2] = value;
    return value
}

function abortOnCannotGrowMemory(requestedSize) {
    abort("OOM")
}

function emscripten_realloc_buffer(size) {
    var PAGE_MULTIPLE = 65536;
    size = alignUp(size, PAGE_MULTIPLE);
    var oldSize = buffer.byteLength;
    try {
        var result = wasmMemory.grow((size - oldSize) / 65536);
        if (result !== (-1 | 0)) {
            buffer = wasmMemory.buffer;
            return true
        } else {
            return false
        }
    } catch (e) {
        return false
    }
}

function _emscripten_resize_heap(requestedSize) {
    var oldSize = _emscripten_get_heap_size();
    var PAGE_MULTIPLE = 65536;
    var LIMIT = 2147483648 - PAGE_MULTIPLE;
    if (requestedSize > LIMIT) {
        return false
    }
    var MIN_TOTAL_MEMORY = 16777216;
    var newSize = Math.max(oldSize, MIN_TOTAL_MEMORY);
    while (newSize < requestedSize) {
        if (newSize <= 536870912) {
            newSize = alignUp(2 * newSize, PAGE_MULTIPLE)
        } else {
            newSize = Math.min(alignUp((3 * newSize + 2147483648) / 4, PAGE_MULTIPLE), LIMIT)
        }
    }
    newSize = Math.min(newSize, 2147418112);
    if (newSize == oldSize) {
        return false
    }
    if (!emscripten_realloc_buffer(newSize)) {
        return false
    }
    updateGlobalBufferViews();
    return true
}

var asmGlobalArg = {};
var asmLibraryArg = {
    "b": abort,
    "c": ___setErrNo,
    "j": _emscripten_get_heap_size,
    "i": _emscripten_memcpy_big,
    "h": _emscripten_resize_heap,
    "g": _pthread_create,
    "f": _pthread_exit,
    "e": _pthread_join,
    "d": abortOnCannotGrowMemory,
    "a": DYNAMICTOP_PTR
};
var asm = Module["asm"](asmGlobalArg, asmLibraryArg, buffer);
Module["asm"] = asm;
Module["_argon2_error_message"] = function () {
    return Module["asm"]["k"].apply(null, arguments)
};
Module["_argon2_hash"] = function () {
    return Module["asm"]["l"].apply(null, arguments)
};
Module["_argon2_verify"] = function () {
    return Module["asm"]["m"].apply(null, arguments)
};
Module["_free"] = function () {
    return Module["asm"]["n"].apply(null, arguments)
};
var _malloc = Module["_malloc"] = function () {
    return Module["asm"]["o"].apply(null, arguments)
};
var stackAlloc = Module["stackAlloc"] = function () {
    return Module["asm"]["p"].apply(null, arguments)
};
Module["asm"] = asm;
Module["allocate"] = allocate;
Module["UTF8ToString"] = UTF8ToString;
Module["ALLOC_NORMAL"] = ALLOC_NORMAL;

function ExitStatus(status) {
    this.name = "ExitStatus";
    this.message = "Program terminated with exit(" + status + ")";
    this.status = status
}

ExitStatus.prototype = new Error;
ExitStatus.prototype.constructor = ExitStatus;
dependenciesFulfilled = function runCaller() {
    if (!Module["calledRun"]) run();
    if (!Module["calledRun"]) dependenciesFulfilled = runCaller
};

function run(args) {
    args = args || Module["arguments"];
    if (runDependencies > 0) {
        return
    }
    preRun();
    if (runDependencies > 0) return;
    if (Module["calledRun"]) return;

    function doRun() {
        if (Module["calledRun"]) return;
        Module["calledRun"] = true;
        if (ABORT) return;
        initRuntime();
        preMain();
        if (Module["onRuntimeInitialized"]) Module["onRuntimeInitialized"]();
        postRun()
    }

    if (Module["setStatus"]) {
        Module["setStatus"]("Running...");
        setTimeout(function () {
            setTimeout(function () {
                Module["setStatus"]("")
            }, 1);
            doRun()
        }, 1)
    } else {
        doRun()
    }
}

Module["run"] = run;

function exit(status, implicit) {
    if (implicit && Module["noExitRuntime"] && status === 0) {
        return
    }
    if (Module["noExitRuntime"]) {
    } else {
        ABORT = true;
        if (Module["onExit"]) Module["onExit"](status)
    }
    Module["quit"](status, new ExitStatus(status))
}

function abort(what) {
    if (Module["onAbort"]) {
        Module["onAbort"](what)
    }
    what += "";
    out(what);
    err(what);
    ABORT = true;
    throw "abort(" + what + "). Build with -s ASSERTIONS=1 for more info."
}

Module["abort"] = abort;
if (Module["preInit"]) {
    if (typeof Module["preInit"] == "function") Module["preInit"] = [Module["preInit"]];
    while (Module["preInit"].length > 0) {
        Module["preInit"].pop()()
    }
}
Module["noExitRuntime"] = true;
run();
if (typeof module !== "undefined") module.exports = Module;
}, function(modId) { var map = {"./sources.js":1576466087056}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1576466087056, function(require, module, exports) {
var base64js = require('./base64.js');

let wasmBinaryBase64 = "AGFzbQEAAAABfBJgAn9/AX9gAn9/AGADf39/AX9gBn98f39/fwF/YAF/AX9gAX8AYAABf2AEf39/fwF/YAJ/fgBgBH9/f38AYAJ+fwF+YA1/f39/f39/f39/f39/AX9gA39/fwBgAn5+AX5gA35/fwF/YAJ+fwF/YAV/f39/fwBgAnx/AXwChwENA2VudgFiAAUDZW52AWMABQNlbnYBZAAEA2VudgFlAAADZW52AWYABQNlbnYBZwAHA2VudgFoAAQDZW52AWkAAgNlbnYBagAGA2VudgxfX3RhYmxlX2Jhc2UDfwADZW52AWEDfwADZW52Bm1lbW9yeQIBgAL//wEDZW52BXRhYmxlAXABCwsDV1YKDQIMEAECAQUCBAQEDwIECQABAAEBAgcEBAEJAQgCABEADAQMAQQHBAIBBQAEAgUBAAMEBQIEDAAADw4BAQUDAQAHAgAMAQQEBQQHAQEMAgQCAgcLBAYHAX8BQZAsCwcZBgFrAFkBbABdAW0AXAFuABEBbwAUAXAAXgkRAQAjAAsLPFA7SDonEj4nOUYKvuEBVhMAIABBwAAgAWuthiAAIAGtiIQLHgAgACABfCABQv////8PgyAAQgGGQv7///8fg358C/wBAQV/IAIEfyAARSABRXIEf0F/BSAAKQNQQgBRBH8gAiAAKALgASIDaiIGQYABSwRAIAMgAEHgAGpqIAFBgAEgA2siBBAPGiAAQoABECYgACAAQeAAahAlIABBADYC4AEgASAEaiEFIAIgBGsiAkGAAUsEfyAGQf99akGAf3EiB0GAAmogA2shBANAIABCgAEQJiAAIAUQJSAFQYABaiEFIAJBgH9qIgJBgAFLDQALIAAoAuABIQMgBkGAfmogB2shAiABIARqBUEAIQMgBQshAQsgAyAAQeAAamogASACEA8aIAAgACgC4AEgAmo2AuABQQAFQX8LCwVBAAsLFgAgACgCAEEgcUUEQCABIAIgABBACwuEAQEDfyMCIQYjAkGAAmokAiAGIQUgBEGAwARxRSACIANKcQRAIAUgAUEYdEEYdSACIANrIgFBgAIgAUGAAkkbEBIaIAFB/wFLBEACfyACIANrIQcDQCAAIAVBgAIQDCABQYB+aiIBQf8BSw0ACyAHC0H/AXEhAQsgACAFIAEQDAsgBiQCCw0AIAAEQCAAIAEQIwsLxgMBA38gAkGAwABOBEAgACABIAIQBxogAA8LIAAhBCAAIAJqIQMgAEEDcSABQQNxRgRAA0AgAEEDcQRAIAJFBEAgBA8LIAAgASwAADoAACAAQQFqIQAgAUEBaiEBIAJBAWshAgwBCwsgA0F8cSICQUBqIQUDQCAAIAVMBEAgACABKAIANgIAIAAgASgCBDYCBCAAIAEoAgg2AgggACABKAIMNgIMIAAgASgCEDYCECAAIAEoAhQ2AhQgACABKAIYNgIYIAAgASgCHDYCHCAAIAEoAiA2AiAgACABKAIkNgIkIAAgASgCKDYCKCAAIAEoAiw2AiwgACABKAIwNgIwIAAgASgCNDYCNCAAIAEoAjg2AjggACABKAI8NgI8IABBQGshACABQUBrIQEMAQsLA0AgACACSARAIAAgASgCADYCACAAQQRqIQAgAUEEaiEBDAELCwUgA0EEayECA0AgACACSARAIAAgASwAADoAACAAIAEsAAE6AAEgACABLAACOgACIAAgASwAAzoAAyAAQQRqIQAgAUEEaiEBDAELCwsDQCAAIANIBEAgACABLAAAOgAAIABBAWohACABQQFqIQEMAQsLIAQLCQAgACABNgAAC+UNAQl/IABFBEAPC0HUHigCACEEIABBeGoiASAAQXxqKAIAIgBBeHEiA2ohBSAAQQFxBH8gASECIAMFAn8gASgCACECIABBA3FFBEAPCyABIAJrIgAgBEkEQA8LIAIgA2ohA0HYHigCACAARgRAIAUoAgQiAUEDcUEDRwRAIAAhASAAIQIgAwwCC0HMHiADNgIAIAUgAUF+cTYCBCAAIANBAXI2AgQgACADaiADNgIADwsgAkEDdiEEIAJBgAJJBEAgACgCCCIBIAAoAgwiAkYEQEHEHkHEHigCAEEBIAR0QX9zcTYCAAUgASACNgIMIAIgATYCCAsgACEBIAAhAiADDAELIAAoAhghByAAKAIMIgEgAEYEQAJAIABBEGoiAkEEaiIEKAIAIgEEQCAEIQIFIAIoAgAiAUUEQEEAIQEMAgsLA0ACQCABQRRqIgQoAgAiBkUEQCABQRBqIgQoAgAiBkUNAQsgBCECIAYhAQwBCwsgAkEANgIACwUgACgCCCICIAE2AgwgASACNgIICyAHBH8gACgCHCICQQJ0QfQgaiIEKAIAIABGBEAgBCABNgIAIAFF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AAwFCyAAIAMoAgA2AiggAUG5HUEDEBcEQEFgIQAFIAFBA2ogAxAcIgFFBEBBYCEADAYLIAAgAygCACICNgIwIAAgAjYCNCABLAAAQSRGBEAgAyAGNgIAIAAoAhAgAyABQQFqEDIiAUUEQEFgIQAMBwsgACADKAIANgIUIAEsAABBJEYEQCADIAc2AgAgACgCACADIAFBAWoQMiIBRQRAQWAhAAwICyAAIAMoAgA2AgQgAEEANgI8IABBQGtBADYCACAAQQA2AkQgAEIANwIYIABCADcCICAAECIiAEUEQEFgQQAgASwAABshAAsFQWAhAAsFQWAhAAsLCwsFQWAhAAsFQWAhAAsLBUFmIQALIAUkAiAAC2YBA38jAiEEIwJB0ABqJAIgBCECIABFIAFFcgRAQWchAwUgACABNgIoIAEgACAAKAIMEFgiA0UEQCACIAEgACgCIBBOIAJBQGtBCBAOIAIgABBPIAJByAAQDkEAIQMLCyAEJAIgAwuAAwEDfyMCIQUjAkGAAmokAiAFIgRB8AFqIQMgAUUgAEVyRQRAIARBwAAQGhogAyABKAIwEBAgBCADQQQQCxogAyABKAIEEBAgBCADQQQQCxogAyABKAIsEBAgBCADQQQQCxogAyABKAIoEBAgBCADQQQQCxogAyABKAI4EBAgBCADQQQQCxogAyACEBAgBCADQQQQCxogAyABKAIMEBAgBCADQQQQCxogASgCCCICBEAgBCACIAEoAgwQCxogASgCREEBcQRAIAEoAgggASgCDBAjIAFBADYCDAsLIAMgASgCFBAQIAQgA0EEEAsaIAEoAhAiAgRAIAQgAiABKAIUEAsaCyADIAEoAhwQECAEIANBBBALGiABKAIYIgIEQCAEIAIgASgCHBALGiABKAJEQQJxBEAgASgCGCABKAIcECMgAUEANgIcCwsgAyABKAIkEBAgBCADQQQQCxogASgCICICBEAgBCACIAEoAiQQCxoLIAQgAEHAABAfGgsgBSQCC58BAQV/IwIhBCMCQYAIaiQCIAQhAiABKAIYBEAgAEFAayEFIABBxABqIQYDQCAFQQAQECAGIAMQECACQYAIIABByAAQJCABKAIAIAEoAhQgA2xBCnRqIAIQMyAFQQEQECACQYAIIABByAAQJCABKAIAIAEoAhQgA2xBAWpBCnRqIAIQMyAD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IGVuY29kZWQgcGFyYW1ldGVycyBhcmUgdG9vIGxvbmcgb3IgdG9vIHNob3J0AFRocmVhZGluZyBmYWlsdXJlAERlY29kaW5nIGZhaWxlZABFbmNvZGluZyBmYWlsZWQATWlzc2luZyBhcmd1bWVudHMAVG9vIG1hbnkgdGhyZWFkcwBOb3QgZW5vdWdoIHRocmVhZHMAT3V0cHV0IHBvaW50ZXIgbWlzbWF0Y2gAVGhlcmUgaXMgbm8gc3VjaCB2ZXJzaW9uIG9mIEFyZ29uMgBBcmdvbjJfQ29udGV4dCBjb250ZXh0IGlzIE5VTEwAVGhlIGFsbG9jYXRlIG1lbW9yeSBjYWxsYmFjayBpcyBOVUxMAFRoZSBmcmVlIG1lbW9yeSBjYWxsYmFjayBpcyBOVUxMAE1lbW9yeSBhbGxvY2F0aW9uIGVycm9yAEFzc29jaWF0ZWQgZGF0YSBwb2ludGVyIGlzIE5VTEwsIGJ1dCBhZCBsZW5ndGggaXMgbm90IDAAU2VjcmV0IHBvaW50ZXIgaXMgTlVMTCwgYnV0IHNlY3JldCBsZW5ndGggaXMgbm90IDAAU2FsdCBwb2ludGVyIGlzIE5VTEwsIGJ1dCBzYWx0IGxlbmd0aCBpcyBub3QgMABQYXNzd29yZCBwb2ludGVyIGlzIE5VTEwsIGJ1dCBwYXNzd29yZCBsZW5ndGggaXMgbm90IDAAVG9vIG1hbnkgbGFuZXMAVG9vIGZldyBsYW5lcwBNZW1vcnkgY29zdCBpcyB0b28gbGFyZ2UATWVtb3J5IGNvc3QgaXMgdG9vIHNtYWxsAFRpbWUgY29zdCBpcyB0b28gbGFyZ2UAVGltZSBjb3N0IGlzIHRvbyBzbWFsbABTZWNyZXQgaXMgdG9vIGxvbmcAU2VjcmV0IGlzIHRvbyBzaG9ydABBc3NvY2lhdGVkIGRhdGEgaXMgdG9vIGxvbmcAQXNzb2NpYXRlZCBkYXRhIGlzIHRvbyBzaG9ydABTYWx0IGlzIHRvbyBsb25nAFNhbHQgaXMgdG9vIHNob3J0AFBhc3N3b3JkIGlzIHRvbyBsb25nAFBhc3N3b3JkIGlzIHRvbyBzaG9ydABPdXRwdXQgaXMgdG9vIGxvbmcAT3V0cHV0IGlzIHRvbyBzaG9ydABPdXRwdXQgcG9pbnRlciBpcyBOVUxMAE9LACR2PQAkbT0ALHQ9ACxwPQAlbHUALSsgICAwWDB4AChudWxsKQAtMFgrMFggMFgtMHgrMHggMHgAaW5mAElORgBuYW4ATkFOAC4=";

module.exports = base64js.toByteArray(wasmBinaryBase64);
}, function(modId) { var map = {"./base64.js":1576466087057}; return __REQUIRE__(map[modId], modId); })
__DEFINE__(1576466087057, function(require, module, exports) {


// copied from https://github.com/beatgammit/base64-js

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

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

function getLens (b64) {
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

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
    var lens = getLens(b64)
    var validLen = lens[0]
    var placeHoldersLen = lens[1]
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
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

function tripletToBase64 (num) {
    return lookup[num >> 18 & 0x3F] +
        lookup[num >> 12 & 0x3F] +
        lookup[num >> 6 & 0x3F] +
        lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
    var tmp
    var output = []
    for (var i = start; i < end; i += 3) {
        tmp =
            ((uint8[i] << 16) & 0xFF0000) +
            ((uint8[i + 1] << 8) & 0xFF00) +
            (uint8[i + 2] & 0xFF)
        output.push(tripletToBase64(tmp))
    }
    return output.join('')
}

function fromByteArray (uint8) {
    var tmp
    var len = uint8.length
    var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
    var parts = []
    var maxChunkLength = 16383 // must be multiple of 3

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
        parts.push(encodeChunk(
            uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
        ))
    }

    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
        tmp = uint8[len - 1]
        parts.push(
            lookup[tmp >> 2] +
            lookup[(tmp << 4) & 0x3F] +
            '=='
        )
    } else if (extraBytes === 2) {
        tmp = (uint8[len - 2] << 8) + uint8[len - 1]
        parts.push(
            lookup[tmp >> 10] +
            lookup[(tmp >> 4) & 0x3F] +
            lookup[(tmp << 2) & 0x3F] +
            '='
        )
    }

    return parts.join('')
}

}, function(modId) { var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1576466087054);
})()
//# sourceMappingURL=index.js.map