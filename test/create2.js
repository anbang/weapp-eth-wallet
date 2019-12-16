(async () => {

    // [93, 11, 94, 137, 135, 115, 103, 250, 150, 221, 143, 162, 66, 135, 42, 109, 55, 231, 194, 28, 141, 237, 113, 163, 75, 155, 184, 74, 227, 60, 10, 170]

    //  [60, 233, 242, 109, 39, 76, 205, 254, 249, 47, 49, 10, 73, 235, 131, 68]

    let crypto = require('crypto')
    let crypto2 = require('crypto-js')
    var cryptoAesCtr = require("crypto-aes-ctr");

    let argon2 = require('argon2-wasm-pro')
    let edPro = require('ed25519-wasm-pro')

    // start

    // const { validateString } = require('internal/validators');
    // 这里开始
    function validateString(value, name) {
        console.log("value, name", value, name)
        if (typeof value !== 'string')
            throw new Error(name, 'string', value);
    }


    // prepareSecretKey
    // var { prepareSecretKey } = require('internal/crypto/keys');
    // const { isArrayBufferView } = require('internal/util/types');
    // const {
    //     ArrayBufferIsView,
    //     ObjectDefineProperty,
    //     Symbol,
    // } = primordials;
    // prepareSecretKey

    // var { kHandle, getArrayBufferView } = require('internal/crypto/util');

    // var { CipherBase } = internalBinding('crypto');
    // var LazyTransform = require('internal/streams/lazy_transform');

    const kKeyType = Symbol('kKeyType');
    const kHandle = Symbol('kHandle');


    // LazyTransform
    function LazyTransform(options) {
        this._options = options;
        this.writable = true;
        this.readable = true;
    }
    // LazyTransform
    // getArrayBufferView
    // This function removes unnecessary frames from Node.js core errors.
    function hideStackFrames(fn) {
        return function hidden(...args) {
            // Make sure the most outer `hideStackFrames()` function is used.
            let setStackFn = false;
            if (excludedStackFn === undefined) {
                excludedStackFn = hidden;
                setStackFn = true;
            }
            try {
                return fn(...args);
            } finally {
                if (setStackFn === true) {
                    excludedStackFn = undefined;
                }
            }
        };
    }
    const getArrayBufferView = hideStackFrames((buffer, name, encoding) => {
        if (typeof buffer === 'string') {
            if (encoding === 'buffer')
                encoding = 'utf8';
            return Buffer.from(buffer, encoding);
        }
        if (!isArrayBufferView(buffer)) {
            // throw new ERR_INVALID_ARG_TYPE(
            throw new Error(
                name,
                ['string', 'Buffer', 'TypedArray', 'DataView'],
                buffer
            );
        }
        return buffer;
    });
    // getArrayBufferView
    //prepareSecretKey start
    class KeyObject {
        constructor(type, handle) {
            if (type !== 'secret' && type !== 'public' && type !== 'private')
                throw new ERR_INVALID_ARG_VALUE('type', type);
            if (typeof handle !== 'object')
                // throw new ERR_INVALID_ARG_TYPE('handle', 'object', handle);
                throw new Error('handle', 'object', handle);

            this[kKeyType] = type;

            // ObjectDefineProperty(this, kHandle, {
            object.assign(this, kHandle, {
                value: handle,
                enumerable: false,
                configurable: false,
                writable: false
            });
        }

        get type() {
            return this[kKeyType];
        }
    }
    function isKeyObject(key) {
        return key instanceof KeyObject;
    }
    function prepareSecretKey(key, bufferOnly = false) {
        console.log('key==', key, key[kHandle])
        // if (!isArrayBufferView(key) && (bufferOnly || typeof key !== 'string')) {
        if ((bufferOnly || typeof key !== 'string')) {
            if (isKeyObject(key) && !bufferOnly) {
                if (key.type !== 'secret')
                    throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(key.type, 'secret');
                return key[kHandle];
            } else {
                // throw new ERR_INVALID_ARG_TYPE(ƒ
                throw new Error(
                    'key',
                    ['Buffer', 'TypedArray', 'DataView',
                        ...(bufferOnly ? [] : ['string', 'KeyObject'])],
                    key);
            }
        }
        return key;
    }
    //prepareSecretKey end

    function getUIntOption(options, key) {
        let value;
        if (options && (value = options[key]) != null) {
            if (value >>> 0 !== value)
                throw new ERR_INVALID_OPT_VALUE(key, value);
            return value;
        }
        return -1;
    }

    function createCipherBase(cipher, credential, options, decipher, iv) {
        const authTagLength = getUIntOption(options, 'authTagLength');

        // this[kHandle] = new CipherBase(decipher);
        // if (iv === undefined) {
        //     this[kHandle].init(cipher, credential, authTagLength);
        // } else {
        //     this[kHandle].initiv(cipher, credential, iv, authTagLength);
        // }
        this._decoder = null;

        LazyTransform.call(this, options);
    }
    function createCipherWithIV(cipher, key, options, decipher, iv) {
        validateString(cipher, 'cipher');
        key = prepareSecretKey(key);
        iv = iv === null ? null : getArrayBufferView(iv, 'iv');
        createCipherBase.call(this, cipher, key, options, decipher, iv);
    }

    function Decipheriv(cipher, key, iv, options) {
        if (!(this instanceof Decipheriv))
            return new Decipheriv(cipher, key, iv, options);

        createCipherWithIV.call(this, cipher, key, options, false, iv);
    }
    function createDecipheriv(cipher, key, iv, options) {
        return new Decipheriv(cipher, key, iv, options);
    }

    function createCipheriv(cipher, key, iv, options) {
        return new Cipheriv(cipher, key, iv, options);
    }
    // end


    async function createAccount(password, COSTNUM) {

        let kdf_salt = crypto.randomBytes(16);
        let iv = crypto.randomBytes(16);
        let privateKey = crypto.randomBytes(32);

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
            console.log("argon------------+")
            let cipher1 = crypto.createCipheriv("aes-256-ctr", Buffer.from(derivePwd.hash.buffer), iv);//加密方法aes-256-ctr
            console.log(cipher1)
            console.log('argon------------+')
            let cipher = createDecipheriv(Buffer.from(derivePwd.hash.buffer), iv);//加密方法aes-256-ctr


            console.log('crypto2-------')
            console.log(cipher)
            console.log('crypto2-------')

            let ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
            let promise = new Promise(function (resolve, reject) {
                try {
                    // 生成公钥
                    edPro.ready(function () {
                        const keypair = edPro.createKeyPair(privateKey)
                        let publicKey = Buffer.from(keypair.publicKey.buffer);

                        //clear privateKey for security, any better methed?
                        crypto.randomFillSync(Buffer.from(derivePwd.hash.buffer));
                        crypto.randomFillSync(privateKey);

                        let accFile = {
                            account: (publicKey),
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

    createAccount(12345678, 256).then(data => {
        console.log(data)
    })
})()